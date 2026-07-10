/*
 * CMFuzz constant-time engine for TRADITIONAL algorithms (dudect-style).
 *
 * Same Welch-t leakage test as ct_dudect.c, but the timed op is a traditional
 * primitive. Demonstrates that constant-time testing is orthogonal to the
 * algorithm family and applies to classic crypto too.
 *
 * Each op declares whether it is EXPECTED to be constant-time; the verdict is
 * then classified against that expectation so a deliberately variable-time
 * demonstrator does not read as a bug:
 *   measured constant + expect ct       -> OK
 *   measured leak     + expect ct        -> FINDING          (real problem)
 *   measured leak     + expect vartime   -> EXPECTED_VARTIME  (by design)
 *   measured constant + expect vartime   -> OK_UNEXPECTEDLY_CT
 *
 * -DCMF_TRAD_OP:
 *   0 = AES-256 block encrypt (AES-NI)        expect ct       -> OK
 *   1 = CRYPTO_memcmp tag compare             expect ct       -> OK
 *   2 = naive byte-by-byte tag compare        expect vartime  -> EXPECTED_VARTIME
 *   3 = AES-CBC PKCS#7 naive unpad (Lucky13)  expect vartime  -> EXPECTED_VARTIME
 *   4 = HMAC-SHA256 over message content      expect ct       -> OK
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#ifndef CMF_TRAD_OP
#define CMF_TRAD_OP 0
#endif
#define N_MEAS 200000
#define N_PERCENTILES 100
#define T_THRESHOLD 4.5

static inline uint64_t rdtsc(void) {
    unsigned hi, lo;
    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi)::"rcx");
    return ((uint64_t)hi << 32) | lo;
}

typedef struct { double n, mean, m2; } tstat_t;
static void t_push(tstat_t *t, double x) {
    t->n += 1.0; double d = x - t->mean; t->mean += d / t->n; t->m2 += d * (x - t->mean);
}
static double welch_t(tstat_t *a, tstat_t *b) {
    if (a->n < 2 || b->n < 2) return 0.0;
    double va = a->m2 / (a->n - 1), vb = b->m2 / (b->n - 1);
    double denom = sqrt(va / a->n + vb / b->n);
    return denom == 0.0 ? 0.0 : (a->mean - b->mean) / denom;
}
static int cmp_u64(const void *x, const void *y) {
    uint64_t a = *(const uint64_t *)x, b = *(const uint64_t *)y;
    return (a > b) - (a < b);
}

/* variable-time compare (deliberately leaky): early-exit on first mismatch */
static int naive_memcmp(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (a[i] != b[i]) return 1;
    return 0;
}

/* naive PKCS#7 unpad validation: reads pad length from the last byte then
 * verifies each padding byte, EARLY-EXITING on the first bad byte. This is the
 * classic Lucky13/padding-oracle shape: validation time depends on where the
 * padding first diverges, so it is expected to be variable-time. */
static volatile uint64_t g_sink;
static int naive_pkcs7_ok(const uint8_t *blk) {
    unsigned pad = blk[15];
    if (pad < 1 || pad > 16) return 0;
    uint64_t acc = 0;
    for (unsigned i = 0; i < pad; i++) {
        /* per-byte processing cost (models the MAC-over-plaintext work whose
         * total scales with how many bytes are examined) so the early-exit
         * difference is above the timer's noise floor. */
        for (int k = 0; k < 48; k++)
            acc = acc * 6364136223846793005ULL + 1442695040888963407ULL + blk[15 - i];
        if (blk[15 - i] != (uint8_t)pad) { g_sink = acc; return 0; }  /* early exit */
    }
    g_sink = acc;
    return 1;
}

int main(void) {
    uint8_t *cls = malloc(N_MEAS);
    uint64_t *cyc = malloc(sizeof(uint64_t) * N_MEAS);
    if (!cls || !cyc) return 1;

    uint8_t key[32], in[16], out[16];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)rand();
    memset(in, 0x42, sizeof in);

    AES_KEY ak;
    AES_set_encrypt_key(key, 256, &ak);

    /* pre-generated random block pool so both classes do an identical memcpy
     * prologue before the timed region (avoids per-class work asymmetry). */
#define BLK_POOL 1024
    uint8_t *pool = malloc(16 * BLK_POOL);
    for (int i = 0; i < BLK_POOL * 16; i++) pool[i] = (uint8_t)rand();

    /* fixed reference tag/buffer (class 0 matches it fully; class 1 differs early).
     * 256 bytes so an early-exit naive compare has a measurable scan-length delta
     * vs a full constant-time compare (a 16-byte delta is below the timer noise). */
#define CMPLEN 256
    uint8_t tag_ref[CMPLEN]; memset(tag_ref, 0xA5, CMPLEN);
    uint8_t tag_rand[CMPLEN];

    const char *opname = (CMF_TRAD_OP == 0) ? "aes256_enc"
                        : (CMF_TRAD_OP == 1) ? "crypto_memcmp"
                        : (CMF_TRAD_OP == 2) ? "naive_memcmp"
                        : (CMF_TRAD_OP == 3) ? "aescbc_pkcs7_oracle"
                                             : "hmac_sha256_msg";
#if CMF_TRAD_OP == 2 || CMF_TRAD_OP == 3
    const char *expect = "vartime";
#else
    const char *expect = "ct";
#endif

    /* HMAC (op4): a random message pool + fixed reference message, both 64B. */
    uint8_t msg_fixed[64]; memset(msg_fixed, 0x33, sizeof msg_fixed);
    uint8_t hkey[32]; for (int i = 0; i < 32; i++) hkey[i] = (uint8_t)rand();
    unsigned char mac[EVP_MAX_MD_SIZE]; unsigned int maclen = 0;
    (void)msg_fixed; (void)hkey; (void)mac; (void)maclen;

    for (size_t i = 0; i < N_MEAS; i++) {
        cls[i] = rand() & 1;
#if CMF_TRAD_OP == 0
        /* both classes memcpy 16 bytes (identical prologue): class 0 from a fixed
         * block, class 1 from the random pool. Only the AES input data differs. */
        uint8_t blk[16];
        size_t idx = (size_t)(rand() % BLK_POOL);   /* both classes call rand() */
        /* both classes read from the pool (identical access pattern); class 0
         * always block 0 (fixed value), class 1 a random block. */
        const uint8_t *src = cls[i] ? (pool + idx * 16) : pool;
        memcpy(blk, src, 16);
        uint64_t t0 = rdtsc();
        AES_encrypt(blk, out, &ak);
        uint64_t t1 = rdtsc();
#elif CMF_TRAD_OP == 1 || CMF_TRAD_OP == 2
        /* class 0: tag equals ref (compare must scan all 16 bytes);
         * class 1: differs in a random early position (leaky compare exits early).
         * Symmetric prologue: BOTH classes memcpy the candidate and call rand()%16;
         * only class 1 actually flips the byte (avoids a per-class work artifact). */
        memcpy(tag_rand, tag_ref, CMPLEN);
        unsigned fpos = (unsigned)(rand() % 8);   /* early byte (both classes call rand) */
        if (cls[i]) tag_rand[fpos] ^= 0xFF;       /* class 1 diverges in first 8 bytes */
        const uint8_t *cand = tag_rand;
        volatile int rc;
        uint64_t t0 = rdtsc();
    #if CMF_TRAD_OP == 1
        rc = CRYPTO_memcmp(cand, tag_ref, CMPLEN);
    #else
        rc = naive_memcmp(cand, tag_ref, CMPLEN);
    #endif
        uint64_t t1 = rdtsc();
        (void)rc;
#elif CMF_TRAD_OP == 3
        /* AES-CBC PKCS#7 padding oracle. Both classes build a valid pad=16 block
         * (identical memset prologue); class 1 corrupts an early-checked byte so
         * the naive unpad early-exits, making validation time leak the padding. */
        uint8_t blk[16]; memset(blk, 0x10, 16);
        (void)(rand() % BLK_POOL);                  /* symmetric rand() call */
        if (cls[i]) blk[14] = 0x00;                 /* diverges at 2nd byte checked */
        volatile int rc;
        uint64_t t0 = rdtsc();
        rc = naive_pkcs7_ok(blk);
        uint64_t t1 = rdtsc();
        (void)rc;
#else /* CMF_TRAD_OP == 4 : HMAC-SHA256 over the message content */
        /* HMAC is constant-time w.r.t. message *content*; both classes memcpy a
         * 64B message (identical prologue) — class 0 fixed, class 1 random — then
         * time the full HMAC. Expect OK (no content-dependent timing). */
        uint8_t msgbuf[64];
        size_t idx = (size_t)(rand() % (BLK_POOL - 4));
        const uint8_t *src = cls[i] ? (pool + idx * 16) : msg_fixed;
        memcpy(msgbuf, src, 64);
        uint64_t t0 = rdtsc();
        HMAC(EVP_sha256(), hkey, 32, msgbuf, 64, mac, &maclen);
        uint64_t t1 = rdtsc();
#endif
        cyc[i] = t1 - t0;
    }

    uint64_t *sorted = malloc(sizeof(uint64_t) * N_MEAS);
    memcpy(sorted, cyc, sizeof(uint64_t) * N_MEAS);
    qsort(sorted, N_MEAS, sizeof(uint64_t), cmp_u64);

    double max_abs_t = 0.0; uint64_t best_cut = 0;
    for (int p = 0; p <= N_PERCENTILES; p++) {
        uint64_t cut = (p == N_PERCENTILES) ? UINT64_MAX
            : sorted[(size_t)((1.0 - pow(0.5, 10.0 * (p + 1) / N_PERCENTILES)) * N_MEAS)];
        tstat_t a = {0}, b = {0};
        for (size_t i = 0; i < N_MEAS; i++) {
            if (cyc[i] > cut) continue;
            if (cls[i]) t_push(&b, (double)cyc[i]); else t_push(&a, (double)cyc[i]);
        }
        double t = welch_t(&a, &b);
        if (fabs(t) > max_abs_t) { max_abs_t = fabs(t); best_cut = cut; }
    }
    int leaked = max_abs_t > T_THRESHOLD;
    const char *verdict;
    if (strcmp(expect, "ct") == 0) verdict = leaked ? "FINDING" : "OK";
    else                          verdict = leaked ? "EXPECTED_VARTIME" : "OK_UNEXPECTEDLY_CT";
    printf("CMF_CT alg=traditional op=%s meas=%d max_t=%.2f cut=%llu expect=%s verdict=%s\n",
           opname, N_MEAS, max_abs_t, (unsigned long long)best_cut, expect, verdict);
    return 0;
}
