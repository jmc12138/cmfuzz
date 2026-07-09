/*
 * CMFuzz shared engine helpers.
 *
 * Provides:
 *   - a deterministic, fuzzer-fed PRNG so key generation / encapsulation become a
 *     reproducible function of the fuzzer input (structure-aware entropy fuzzing);
 *   - a tiny byte-reader for structure-aware decoding of the libFuzzer buffer;
 *   - metamorphic-oracle assertion macros that print a structured VIOLATION line
 *     and abort() so libFuzzer records the crashing input.
 */
#ifndef CMFUZZ_COMMON_H
#define CMFUZZ_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ---- fuzzer-fed deterministic PRNG ------------------------------------- */
/* A SplitMix64-based stream keyed by the current fuzzer input. Deterministic:
 * identical seeds yield identical keypairs, which is what makes a crashing input
 * reproducible and lets metamorphic relations hold by construction. */
typedef struct {
    uint64_t state;
} cmf_prng_t;

static cmf_prng_t g_cmf_prng;

static inline uint64_t cmf_splitmix64(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static inline void cmf_prng_seed(const uint8_t *buf, size_t len) {
    uint64_t s = 0xcbf29ce484222325ULL; /* FNV offset basis */
    for (size_t i = 0; i < len; i++) { s ^= buf[i]; s *= 0x100000001b3ULL; }
    g_cmf_prng.state = s ? s : 0x1234567890abcdefULL;
}

/* signature matches OQS_randombytes_custom_algorithm's expected callback */
static inline void cmf_randombytes(uint8_t *out, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint64_t r = cmf_splitmix64(&g_cmf_prng.state);
        size_t chunk = (n - i < 8) ? (n - i) : 8;
        memcpy(out + i, &r, chunk);
        i += chunk;
    }
}

/* ---- structure-aware byte reader --------------------------------------- */
typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} cmf_reader_t;

static inline void cmf_reader_init(cmf_reader_t *r, const uint8_t *d, size_t l) {
    r->data = d; r->len = l; r->pos = 0;
}
static inline uint8_t cmf_u8(cmf_reader_t *r) {
    return r->pos < r->len ? r->data[r->pos++] : 0;
}
static inline uint32_t cmf_u32(cmf_reader_t *r) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v = (v << 8) | cmf_u8(r);
    return v;
}
/* remaining bytes as a slice */
static inline size_t cmf_rest(cmf_reader_t *r, const uint8_t **p) {
    *p = r->data + r->pos;
    size_t n = r->len - r->pos;
    r->pos = r->len;
    return n;
}

/* ---- metamorphic-oracle assertions ------------------------------------- */
/* Distinguishes logical (metamorphic) violations from memory bugs (ASan/UBSan
 * catch the latter). A logical violation prints a machine-parseable line then
 * aborts so the fuzzer saves the reproducer. */
#define CMF_VIOLATION(alg, oracle, msg)                                        \
    do {                                                                       \
        fprintf(stderr, "CMF_VIOLATION alg=%s oracle=%s msg=%s\n",             \
                (alg), (oracle), (msg));                                       \
        abort();                                                               \
    } while (0)

#define CMF_ASSERT(cond, alg, oracle, msg)                                     \
    do { if (!(cond)) CMF_VIOLATION(alg, oracle, msg); } while (0)

#endif /* CMFUZZ_COMMON_H */
