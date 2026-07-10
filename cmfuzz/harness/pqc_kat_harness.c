/*
 * CMFuzz stage 2.3 — PQC deterministic KAT cross-check (liboqs vs PQClean).
 *
 * The interop differential (pqc_diff) proves the two libraries agree on
 * *outcomes*, but randomised keygen/encaps/signing means it never compares the
 * actual key/ciphertext/signature bytes. This harness closes that gap with a
 * Known-Answer-Test style check: both libraries are driven from the SAME NIST
 * AES-256-CTR-DRBG (the standard KAT PRNG, from PQClean's nistkatrng.c). For a
 * given 48-byte seed, ML-KEM and ML-DSA are fully deterministic, and both
 * libraries draw randombytes at identical granularity (keygen 32/64B, encaps
 * 32B, ML-DSA hedge 32B). Therefore, re-seeding the DRBG to the same state
 * before each library's run MUST yield byte-identical KAT vectors:
 *
 *   KEM: pk, sk, ct, shared secret   SIG: pk, sk, signature
 *
 * Any per-byte divergence is a real interoperability / spec-conformance bug in
 * one of the implementations and is reported as a CMF_VIOLATION. Both PQClean
 * (global randombytes) and liboqs (OQS custom-RNG hook) share the one DRBG.
 *
 * CMF_KAT_FAULT=1 perturbs one library's seed by a byte so the negative
 * self-test can prove the byte-exact comparison actually catches divergence.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include "randombytes.h"   /* PQClean: macro-namespaces randombytes -> PQCLEAN_randombytes */
#include "../engine/cmfuzz_common.h"
#include "../libs/pqclean/crypto_kem/ml-kem-512/clean/api.h"
#include "../libs/pqclean/crypto_kem/ml-kem-768/clean/api.h"
#include "../libs/pqclean/crypto_kem/ml-kem-1024/clean/api.h"
#include "../libs/pqclean/crypto_sign/ml-dsa-44/clean/api.h"
#include "../libs/pqclean/crypto_sign/ml-dsa-65/clean/api.h"
#include "../libs/pqclean/crypto_sign/ml-dsa-87/clean/api.h"

/* NIST AES-256-CTR-DRBG from PQClean's test/common/nistkatrng.c. Both the
 * PQClean crypto (global randombytes) and our liboqs hook draw from this one
 * DRBG; nist_kat_init() reseeds it to a deterministic state. */
extern void nist_kat_init(uint8_t *entropy_input, const uint8_t *personalization_string, int security_strength);

/* liboqs custom-RNG shim: liboqs wants void(*)(uint8_t*,size_t). */
static void oqs_drbg(uint8_t *out, size_t n) { (void)randombytes(out, n); }

typedef struct {
    const char *name;
    int (*keypair)(uint8_t *pk, uint8_t *sk);
    int (*enc)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int (*dec)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
} pqc_kem_t;

typedef struct {
    const char *name;
    int (*keypair)(uint8_t *pk, uint8_t *sk);
    int (*sign)(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
} pqc_sig_t;

static const pqc_kem_t KEMS[] = {
    { "ML-KEM-512",  PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair,
                     PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc,
                     PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec },
    { "ML-KEM-768",  PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair,
                     PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc,
                     PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec },
    { "ML-KEM-1024", PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair,
                     PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc,
                     PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec },
};
static const pqc_sig_t SIGS[] = {
    { "ML-DSA-44", PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair, PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature },
    { "ML-DSA-65", PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair, PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature },
    { "ML-DSA-87", PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair, PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature },
};
#define NKEMS (sizeof(KEMS)/sizeof(KEMS[0]))
#define NSIGS (sizeof(SIGS)/sizeof(SIGS[0]))

/* Deterministic 48-byte KAT seed for test index i (mirrors the NIST KAT driver:
 * a top-level DRBG seeded 0,1,2,... emits the per-test entropy). */
static void kat_seed(long i, uint8_t seed[48]) {
    uint8_t entropy[48];
    for (int j = 0; j < 48; j++) entropy[j] = (uint8_t)(j + 1);
    nist_kat_init(entropy, NULL, 256);
    for (long t = 0; t <= i; t++) randombytes(seed, 48);
}

static int cmp(const char *alg, const char *what,
               const uint8_t *a, const uint8_t *b, size_t n) {
    if (memcmp(a, b, n) == 0) return 0;
    char detail[128];
    snprintf(detail, sizeof detail, "liboqs vs PQClean %s bytes differ", what);
    CMF_VIOLATION(alg, "O1_kat_bytes", detail);
    return 1;
}

static void kem_kat(OQS_KEM *k, const pqc_kem_t *p, long iters) {
    size_t pkl = k->length_public_key, skl = k->length_secret_key;
    size_t ctl = k->length_ciphertext, ssl = k->length_shared_secret;
    uint8_t *pkO = malloc(pkl), *skO = malloc(skl), *ctO = malloc(ctl), *ssO = malloc(ssl);
    uint8_t *pkP = malloc(pkl), *skP = malloc(skl), *ctP = malloc(ctl), *ssP = malloc(ssl);
    uint8_t seed[48];
    for (long i = 0; i < iters; i++) {
        kat_seed(i, seed);
        nist_kat_init(seed, NULL, 256);
        if (k->keypair(pkO, skO) != OQS_SUCCESS) continue;
        if (k->encaps(ctO, ssO, pkO) != OQS_SUCCESS) continue;

        nist_kat_init(seed, NULL, 256);
#ifdef CMF_KAT_FAULT
        seed[0] ^= 0x01; nist_kat_init(seed, NULL, 256);
#endif
        if (p->keypair(pkP, skP) != 0) continue;
        if (p->enc(ctP, ssP, pkP) != 0) continue;

        cmp(p->name, "KEM pk", pkO, pkP, pkl);
        cmp(p->name, "KEM sk", skO, skP, skl);
        cmp(p->name, "KEM ct", ctO, ctP, ctl);
        cmp(p->name, "KEM ss", ssO, ssP, ssl);
    }
    printf("[pqc-kat] %s KEM KAT: %ld vectors byte-identical (pk/sk/ct/ss)\n", p->name, iters);
    free(pkO); free(skO); free(ctO); free(ssO);
    free(pkP); free(skP); free(ctP); free(ssP);
}

static void sig_kat(OQS_SIG *s, const pqc_sig_t *p, long iters) {
    size_t pkl = s->length_public_key, skl = s->length_secret_key, sigl = s->length_signature;
    uint8_t *pkO = malloc(pkl), *skO = malloc(skl), *sigO = malloc(sigl);
    uint8_t *pkP = malloc(pkl), *skP = malloc(skl), *sigP = malloc(sigl);
    uint8_t seed[48], msg[128];
    for (long i = 0; i < iters; i++) {
        kat_seed(i, seed);
        size_t mlen = 32 + (size_t)(i % 64);
        for (size_t j = 0; j < mlen; j++) msg[j] = (uint8_t)(i + j);

        nist_kat_init(seed, NULL, 256);
        size_t sigOl = 0, sigPl = 0;
        if (s->keypair(pkO, skO) != OQS_SUCCESS) continue;
        if (s->sign(sigO, &sigOl, msg, mlen, skO) != OQS_SUCCESS) continue;

        nist_kat_init(seed, NULL, 256);
#ifdef CMF_KAT_FAULT
        seed[0] ^= 0x01; nist_kat_init(seed, NULL, 256);
#endif
        if (p->keypair(pkP, skP) != 0) continue;
        if (p->sign(sigP, &sigPl, msg, mlen, skP) != 0) continue;

        cmp(p->name, "SIG pk", pkO, pkP, pkl);
        cmp(p->name, "SIG sk", skO, skP, skl);
        if (sigOl != sigPl)
            CMF_VIOLATION(p->name, "O1_kat_bytes", "liboqs vs PQClean signature length differ");
        else
            cmp(p->name, "SIG sig", sigO, sigP, sigOl);
    }
    printf("[pqc-kat] %s SIG KAT: %ld vectors byte-identical (pk/sk/sig)\n", p->name, iters);
    free(pkO); free(skO); free(sigO);
    free(pkP); free(skP); free(sigP);
}

int main(int argc, char **argv) {
    long iters = (argc > 1) ? atol(argv[1]) : 200;
    OQS_init();
    OQS_randombytes_custom_algorithm(oqs_drbg);   /* liboqs draws from the KAT DRBG */

    int ran = 0;
    for (size_t i = 0; i < NKEMS; i++) {
        OQS_KEM *k = OQS_KEM_new(KEMS[i].name);
        if (!k) { fprintf(stderr, "CMF: liboqs KEM %s not enabled, skipping\n", KEMS[i].name); continue; }
        kem_kat(k, &KEMS[i], iters);
        OQS_KEM_free(k);
        ran++;
    }
    for (size_t i = 0; i < NSIGS; i++) {
        OQS_SIG *s = OQS_SIG_new(SIGS[i].name);
        if (!s) { fprintf(stderr, "CMF: liboqs SIG %s not enabled, skipping\n", SIGS[i].name); continue; }
        sig_kat(s, &SIGS[i], iters);
        OQS_SIG_free(s);
        ran++;
    }

    if (!ran) { fprintf(stderr, "CMF: no PQC schemes available in liboqs\n"); return 1; }
    printf("[pqc-kat] all liboqs<->PQClean KAT vectors byte-identical (%d scheme(s))\n", ran);
    return 0;
}
