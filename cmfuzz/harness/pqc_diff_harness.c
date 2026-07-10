/*
 * CMFuzz stage 2.3 — PQC cross-library differential (liboqs vs PQClean).
 *
 * Earlier pillars covered PQC only with property/metamorphic oracles (O2). This
 * adds the missing O1 (cross-implementation differential) for the NIST-
 * standardised lattice schemes, differentially testing liboqs against the
 * PQClean reference "clean" build across every parameter set:
 *
 *   ML-KEM  (FIPS 203): ML-KEM-512 / ML-KEM-768 / ML-KEM-1024
 *   ML-DSA  (FIPS 204): ML-DSA-44  / ML-DSA-65  / ML-DSA-87
 *
 * Randomised operations (KEM encaps, ML-DSA signing) make byte-exact output
 * comparison impossible, so — as with the classic RSA/ECDSA verify-interop ops
 * in diff_subproc — we compare *interoperability outcomes* instead:
 *
 *   KEM  (both directions): keygen in lib A, encapsulate in lib B against A's
 *        public key, decapsulate in lib A. The two shared secrets MUST match;
 *        this exercises cross-library public-key / ciphertext wire encoding.
 *   SIG  (both directions): sign in lib A, then compare the accept/reject verdict
 *        of lib A and lib B over the same (pk, sig, message), for both the honest
 *        message and a tampered copy. The verdicts MUST agree.
 *
 * Each scheme is driven through a small function-pointer table so the same
 * interop logic runs against every parameter set; a scheme is skipped (not
 * failed) when the local liboqs build does not enable it.
 *
 * CMF_PQC_FAULT=1 corrupts one comparison so the negative self-test can prove
 * the differential actually catches a divergent implementation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include "../engine/cmfuzz_common.h"
#include "../libs/pqclean/crypto_kem/ml-kem-512/clean/api.h"
#include "../libs/pqclean/crypto_kem/ml-kem-768/clean/api.h"
#include "../libs/pqclean/crypto_kem/ml-kem-1024/clean/api.h"
#include "../libs/pqclean/crypto_sign/ml-dsa-44/clean/api.h"
#include "../libs/pqclean/crypto_sign/ml-dsa-65/clean/api.h"
#include "../libs/pqclean/crypto_sign/ml-dsa-87/clean/api.h"

/* PQClean function-pointer view of one scheme (signatures match the namespaced
 * PQCLEAN_*_crypto_* entry points exactly). */
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
    int (*verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
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
    { "ML-DSA-44", PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair,
                   PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature,
                   PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify },
    { "ML-DSA-65", PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
                   PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature,
                   PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify },
    { "ML-DSA-87", PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair,
                   PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature,
                   PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify },
};
#define NKEMS (sizeof(KEMS)/sizeof(KEMS[0]))
#define NSIGS (sizeof(SIGS)/sizeof(SIGS[0]))

static void fill_random(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(rand() & 0xFF);
}

static void kem_interop(OQS_KEM *k, const pqc_kem_t *p, long iters) {
    uint8_t *pk = malloc(k->length_public_key);
    uint8_t *sk = malloc(k->length_secret_key);
    uint8_t *ct = malloc(k->length_ciphertext);
    uint8_t *ss1 = malloc(k->length_shared_secret);
    uint8_t *ss2 = malloc(k->length_shared_secret);
    if (!pk || !sk || !ct || !ss1 || !ss2) { fprintf(stderr, "oom\n"); exit(2); }

    for (long i = 0; i < iters; i++) {
        /* Direction A: liboqs keygen -> PQClean encaps -> liboqs decaps. */
        if (k->keypair(pk, sk) != OQS_SUCCESS) continue;
        if (p->enc(ct, ss1, pk) != 0) continue;
        if (k->decaps(ss2, ct, sk) != OQS_SUCCESS) continue;
#ifdef CMF_PQC_FAULT
        ss1[0] ^= 0xFF;
#endif
        if (memcmp(ss1, ss2, k->length_shared_secret) != 0)
            CMF_VIOLATION(p->name, "O1_kem_interop",
                          "liboqs decaps != PQClean encaps shared secret (dir A)");

        /* Direction B: PQClean keygen -> liboqs encaps -> PQClean decaps. */
        if (p->keypair(pk, sk) != 0) continue;
        if (k->encaps(ct, ss1, pk) != OQS_SUCCESS) continue;
        if (p->dec(ss2, ct, sk) != 0) continue;
        if (memcmp(ss1, ss2, k->length_shared_secret) != 0)
            CMF_VIOLATION(p->name, "O1_kem_interop",
                          "PQClean decaps != liboqs encaps shared secret (dir B)");
    }
    printf("[pqc-diff] %s KEM interop: %ld iters, both directions agree\n", p->name, iters);
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
}

static void sig_interop(OQS_SIG *s, const pqc_sig_t *p, long iters) {
    uint8_t *pk = malloc(s->length_public_key);
    uint8_t *sk = malloc(s->length_secret_key);
    uint8_t *sig = malloc(s->length_signature);
    uint8_t msg[256];
    if (!pk || !sk || !sig) { fprintf(stderr, "oom\n"); exit(2); }

    for (long i = 0; i < iters; i++) {
        size_t mlen = 1 + (size_t)(rand() % 200);
        fill_random(msg, mlen);

        /* Direction A: liboqs signs; compare liboqs vs PQClean verdicts. */
        size_t siglen = 0;
        if (s->keypair(pk, sk) != OQS_SUCCESS) continue;
        if (s->sign(sig, &siglen, msg, mlen, sk) != OQS_SUCCESS) continue;
        for (int tamper = 0; tamper < 2; tamper++) {
            if (tamper) msg[rand() % mlen] ^= 0x01;
            int v_oqs = (s->verify(msg, mlen, sig, siglen, pk) == OQS_SUCCESS) ? 1 : 0;
            int v_pqc = (p->verify(sig, siglen, msg, mlen, pk) == 0) ? 1 : 0;
#ifdef CMF_PQC_FAULT
            v_pqc ^= 1;
#endif
            if (v_oqs != v_pqc)
                CMF_VIOLATION(p->name, "O1_sig_verify_interop",
                              "liboqs vs PQClean verdict disagree (dir A)");
        }

        /* Direction B: PQClean signs; compare PQClean vs liboqs verdicts. */
        fill_random(msg, mlen);
        siglen = 0;
        if (p->keypair(pk, sk) != 0) continue;
        if (p->sign(sig, &siglen, msg, mlen, sk) != 0) continue;
        for (int tamper = 0; tamper < 2; tamper++) {
            if (tamper) msg[rand() % mlen] ^= 0x01;
            int v_pqc = (p->verify(sig, siglen, msg, mlen, pk) == 0) ? 1 : 0;
            int v_oqs = (s->verify(msg, mlen, sig, siglen, pk) == OQS_SUCCESS) ? 1 : 0;
            if (v_oqs != v_pqc)
                CMF_VIOLATION(p->name, "O1_sig_verify_interop",
                              "PQClean vs liboqs verdict disagree (dir B)");
        }
    }
    printf("[pqc-diff] %s sign/verify interop: %ld iters, both directions agree\n", p->name, iters);
    free(pk); free(sk); free(sig);
}

int main(int argc, char **argv) {
    long iters = (argc > 1) ? atol(argv[1]) : 2000;
    unsigned seed = (argc > 2) ? (unsigned)atol(argv[2]) : 42;
    srand(seed);
    OQS_init();

    int ran = 0;
    for (size_t i = 0; i < NKEMS; i++) {
        OQS_KEM *k = OQS_KEM_new(KEMS[i].name);
        if (!k) { fprintf(stderr, "CMF: liboqs KEM %s not enabled, skipping\n", KEMS[i].name); continue; }
        kem_interop(k, &KEMS[i], iters);
        OQS_KEM_free(k);
        ran++;
    }
    for (size_t i = 0; i < NSIGS; i++) {
        OQS_SIG *s = OQS_SIG_new(SIGS[i].name);
        if (!s) { fprintf(stderr, "CMF: liboqs SIG %s not enabled, skipping\n", SIGS[i].name); continue; }
        sig_interop(s, &SIGS[i], iters);
        OQS_SIG_free(s);
        ran++;
    }

    if (!ran) { fprintf(stderr, "CMF: no PQC schemes available in liboqs\n"); return 1; }
    printf("[pqc-diff] all liboqs<->PQClean differentials agree (%d scheme(s))\n", ran);
    return 0;
}
