/*
 * CMFuzz constant-time engine for TRADITIONAL algorithms (dudect-style).
 *
 * Same Welch-t leakage test as ct_dudect.c, but the timed op is a traditional
 * primitive. Demonstrates that constant-time testing is orthogonal to the
 * algorithm family and applies to classic crypto too.
 *
 * -DCMF_TRAD_OP:
 *   0 = AES-256 block encrypt (AES-NI)        -> expect OK (constant-time)
 *   1 = CRYPTO_memcmp tag compare             -> expect OK (constant-time)
 *   2 = naive byte-by-byte tag compare (early-exit, variable-time)
 *                                             -> expect LEAK (demonstrates detection)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
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

    /* fixed reference tag (class 0 matches it fully; class 1 differs early) */
    uint8_t tag_ref[16]; memset(tag_ref, 0xA5, 16);
    uint8_t tag_fixed[16]; memcpy(tag_fixed, tag_ref, 16);   /* equal */
    uint8_t tag_rand[16];

    const char *opname = (CMF_TRAD_OP == 0) ? "aes256_enc"
                        : (CMF_TRAD_OP == 1) ? "crypto_memcmp"
                                             : "naive_memcmp";

    for (size_t i = 0; i < N_MEAS; i++) {
        cls[i] = rand() & 1;
#if CMF_TRAD_OP == 0
        /* both classes memcpy 16 bytes (identical prologue): class 0 from a fixed
         * block, class 1 from the random pool. Only the AES input data differs. */
        uint8_t blk[16];
        size_t idx = (size_t)(rand() % BLK_POOL);   /* both classes call rand() */
        const uint8_t *src = cls[i] ? (pool + idx * 16) : in;
        memcpy(blk, src, 16);
        uint64_t t0 = rdtsc();
        AES_encrypt(blk, out, &ak);
        uint64_t t1 = rdtsc();
#else
        /* class 0: tag equals ref (compare must scan all 16 bytes);
         * class 1: differs in a random early position (leaky compare exits early) */
        const uint8_t *cand;
        if (cls[i]) {
            memcpy(tag_rand, tag_ref, 16);
            tag_rand[rand() % 16] ^= 0xFF;
            cand = tag_rand;
        } else cand = tag_fixed;
        volatile int rc;
        uint64_t t0 = rdtsc();
    #if CMF_TRAD_OP == 1
        rc = CRYPTO_memcmp(cand, tag_ref, 16);
    #else
        rc = naive_memcmp(cand, tag_ref, 16);
    #endif
        uint64_t t1 = rdtsc();
        (void)rc;
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
    const char *verdict = max_abs_t > T_THRESHOLD ? "LEAK" : "OK";
    printf("CMF_CT alg=traditional op=%s meas=%d max_t=%.2f cut=%llu verdict=%s\n",
           opname, N_MEAS, max_abs_t, (unsigned long long)best_cut, verdict);
    return 0;
}
