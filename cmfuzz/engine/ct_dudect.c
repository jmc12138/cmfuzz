/*
 * CMFuzz constant-time engine (Pillar 2, timing half).
 *
 * A dudect-style leakage test: two input classes (fixed vs random), measure the
 * target operation's cycle count, and apply Welch's t-test with higher-order
 * percentile cropping (as in Reparaz et al.'s dudect). |t| > 4.5 => the timing
 * distribution depends on the class, i.e. an input-dependent (potential timing
 * side-channel) code path.
 *
 * Compile per algorithm/op with -DCMF_ALG, -DCMF_KIND (0=KEM decaps, 1=SIG sign).
 * This is intentionally separate from the libFuzzer functional harness because
 * coverage instrumentation perturbs timing; both share the same specs/generator.
 */
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifndef CMF_ALG
#define CMF_ALG "ML-KEM-768"
#endif
#ifndef CMF_KIND
#define CMF_KIND 0   /* 0 = KEM decaps, 1 = SIG sign */
#endif

#define N_MEAS   200000
#define N_PERCENTILES 100
#define T_THRESHOLD 4.5

static inline uint64_t rdtsc(void) {
    unsigned hi, lo;
    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi)::"rcx");
    return ((uint64_t)hi << 32) | lo;
}

/* Welch's t-test accumulators for two classes */
typedef struct { double n, mean, m2; } tstat_t;
static void t_push(tstat_t *t, double x) {
    t->n += 1.0;
    double d = x - t->mean;
    t->mean += d / t->n;
    t->m2 += d * (x - t->mean);
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

/* Whether this algorithm/op is EXPECTED to be constant-time.
 *  - KEM decapsulation processes the secret key and MUST be constant-time
 *    (a timing leak here is a genuine FINDING, e.g. an implicit-reject bug).
 *  - Lattice signature signing is variable-time BY DESIGN: ML-DSA/Dilithium use
 *    rejection sampling and Falcon uses floating-point Gaussian sampling, so
 *    their signing time depends on secret-derived values; a timing signal is
 *    EXPECTED_VARTIME, not a bug. Hash-based SLH-DSA/SPHINCS+ signing is
 *    constant-time and so is still expected to be CT. */
static int expect_constant_time(void) {
#if CMF_KIND == 0
    return 1;
#else
    const char *a = CMF_ALG;
    if (strstr(a, "ML-DSA") || strstr(a, "Dilithium") || strstr(a, "Falcon"))
        return 0;
    return 1;
#endif
}

int main(void) {
    OQS_init();
    uint8_t *cls = malloc(N_MEAS);            /* class label per measurement */
    uint64_t *cyc = malloc(sizeof(uint64_t) * N_MEAS);
    if (!cls || !cyc) return 1;

#if CMF_KIND == 0
    OQS_KEM *o = OQS_KEM_new(CMF_ALG);
    if (!o) { fprintf(stderr, "alg %s not enabled\n", CMF_ALG); return 0; }
    uint8_t *pk = malloc(o->length_public_key), *sk = malloc(o->length_secret_key);
    uint8_t *ss = malloc(o->length_shared_secret);
    uint8_t *ct_fixed = malloc(o->length_ciphertext);
    uint8_t *ct_rand  = malloc(o->length_ciphertext);
    uint8_t *ct = malloc(o->length_ciphertext);
    o->keypair(pk, sk);
    /* class 0: a fixed valid ciphertext; class 1: random ciphertexts drawn from
     * a pre-generated pool. Both classes perform an identical memcpy inside the
     * timed region's prologue, so there is no per-class work asymmetry before
     * the measurement (a common dudect pitfall). */
    o->encaps(ct_fixed, ss, pk);
    size_t ctlen = o->length_ciphertext;
    #define CT_POOL 1024
    uint8_t *pool = malloc(ctlen * CT_POOL);
    for (int i = 0; i < CT_POOL; i++) OQS_randombytes(pool + (size_t)i * ctlen, ctlen);
#else
    OQS_SIG *o = OQS_SIG_new(CMF_ALG);
    if (!o) { fprintf(stderr, "alg %s not enabled\n", CMF_ALG); return 0; }
    uint8_t *pk = malloc(o->length_public_key), *sk = malloc(o->length_secret_key);
    uint8_t *sig = malloc(o->length_signature);
    size_t siglen;
    uint8_t msg_fixed[32]; memset(msg_fixed, 0x42, sizeof msg_fixed);
    uint8_t msg_rand[32];  uint8_t msg[32];
    o->keypair(pk, sk);
#endif

    /* assign classes randomly and run measurements */
    for (size_t i = 0; i < N_MEAS; i++) {
        cls[i] = rand() & 1;
#if CMF_KIND == 0
        /* identical memcpy work for both classes */
        const uint8_t *src = cls[i] ? (pool + (size_t)(rand() % CT_POOL) * ctlen)
                                    : ct_fixed;
        memcpy(ct, src, ctlen);
        uint64_t t0 = rdtsc();
        o->decaps(ss, ct, sk);
        uint64_t t1 = rdtsc();
#else
        memcpy(msg, cls[i] ? msg_rand : msg_fixed, 32);
        if (cls[i]) OQS_randombytes(msg_rand, 32);
        uint64_t t0 = rdtsc();
        o->sign(sig, &siglen, msg, 32, sk);
        uint64_t t1 = rdtsc();
#endif
        cyc[i] = t1 - t0;
    }

    /* crop by high percentiles to reduce measurement-tail noise (dudect trick) */
    uint64_t *sorted = malloc(sizeof(uint64_t) * N_MEAS);
    memcpy(sorted, cyc, sizeof(uint64_t) * N_MEAS);
    qsort(sorted, N_MEAS, sizeof(uint64_t), cmp_u64);

    double max_abs_t = 0.0; uint64_t best_cut = 0;
    for (int p = 0; p <= N_PERCENTILES; p++) {
        uint64_t cut = (p == N_PERCENTILES)
            ? UINT64_MAX
            : sorted[(size_t)((1.0 - pow(0.5, 10.0 * (p + 1) / N_PERCENTILES)) * N_MEAS)];
        tstat_t a = {0}, b = {0};
        for (size_t i = 0; i < N_MEAS; i++) {
            if (cyc[i] > cut) continue;
            if (cls[i]) t_push(&b, (double)cyc[i]);
            else        t_push(&a, (double)cyc[i]);
        }
        double t = welch_t(&a, &b);
        if (fabs(t) > max_abs_t) { max_abs_t = fabs(t); best_cut = cut; }
    }

    int leaked = max_abs_t > T_THRESHOLD;
    int ect = expect_constant_time();
    const char *expect = ect ? "ct" : "vartime";
    const char *verdict = ect ? (leaked ? "FINDING" : "OK")
                              : (leaked ? "EXPECTED_VARTIME" : "OK_UNEXPECTEDLY_CT");
    printf("CMF_CT alg=%s op=%s meas=%d max_t=%.2f cut=%llu expect=%s verdict=%s\n",
           CMF_ALG, (CMF_KIND == 0 ? "decaps" : "sign"),
           N_MEAS, max_abs_t, (unsigned long long)best_cut, expect, verdict);
    return 0;
}
