/*
 * CMFuzz stage 2.3 — PQC cross-library differential (liboqs vs PQClean).
 *
 * Earlier pillars covered PQC only with property/metamorphic oracles (O2). This
 * adds the missing O1 (cross-implementation differential) for the two
 * NIST-standardised schemes ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204),
 * differentially testing liboqs against the PQClean reference "clean" build.
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
 * CMF_PQC_FAULT=1 corrupts one comparison so the negative self-test can prove
 * the differential actually catches a divergent implementation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include "../engine/cmfuzz_common.h"
#include "../libs/pqclean/crypto_kem/ml-kem-768/clean/api.h"
#include "../libs/pqclean/crypto_sign/ml-dsa-65/clean/api.h"

#define MLKEM "ML-KEM-768"
#define MLDSA "ML-DSA-65"

static void fill_random(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(rand() & 0xFF);
}

static void kem_interop(OQS_KEM *k, long iters) {
    uint8_t *pk = malloc(k->length_public_key);
    uint8_t *sk = malloc(k->length_secret_key);
    uint8_t *ct = malloc(k->length_ciphertext);
    uint8_t *ss1 = malloc(k->length_shared_secret);
    uint8_t *ss2 = malloc(k->length_shared_secret);
    if (!pk || !sk || !ct || !ss1 || !ss2) { fprintf(stderr, "oom\n"); exit(2); }

    for (long i = 0; i < iters; i++) {
        /* Direction A: liboqs keygen -> PQClean encaps -> liboqs decaps. */
        if (k->keypair(pk, sk) != OQS_SUCCESS) continue;
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss1, pk) != 0) continue;
        if (k->decaps(ss2, ct, sk) != OQS_SUCCESS) continue;
#ifdef CMF_PQC_FAULT
        ss1[0] ^= 0xFF;
#endif
        if (memcmp(ss1, ss2, k->length_shared_secret) != 0)
            CMF_VIOLATION(MLKEM, "O1_kem_interop",
                          "liboqs decaps != PQClean encaps shared secret (dir A)");

        /* Direction B: PQClean keygen -> liboqs encaps -> PQClean decaps. */
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk) != 0) continue;
        if (k->encaps(ct, ss1, pk) != OQS_SUCCESS) continue;
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2, ct, sk) != 0) continue;
        if (memcmp(ss1, ss2, k->length_shared_secret) != 0)
            CMF_VIOLATION(MLKEM, "O1_kem_interop",
                          "PQClean decaps != liboqs encaps shared secret (dir B)");
    }
    printf("[pqc-diff] %s KEM interop: %ld iters, both directions agree\n", MLKEM, iters);
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
}

static void sig_interop(OQS_SIG *s, long iters) {
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
            int v_pqc = (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, msg, mlen, pk) == 0) ? 1 : 0;
#ifdef CMF_PQC_FAULT
            v_pqc ^= 1;
#endif
            if (v_oqs != v_pqc)
                CMF_VIOLATION(MLDSA, "O1_sig_verify_interop",
                              "liboqs vs PQClean verdict disagree (dir A)");
        }

        /* Direction B: PQClean signs; compare PQClean vs liboqs verdicts. */
        fill_random(msg, mlen);
        siglen = 0;
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk) != 0) continue;
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, &siglen, msg, mlen, sk) != 0) continue;
        for (int tamper = 0; tamper < 2; tamper++) {
            if (tamper) msg[rand() % mlen] ^= 0x01;
            int v_pqc = (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, msg, mlen, pk) == 0) ? 1 : 0;
            int v_oqs = (s->verify(msg, mlen, sig, siglen, pk) == OQS_SUCCESS) ? 1 : 0;
            if (v_oqs != v_pqc)
                CMF_VIOLATION(MLDSA, "O1_sig_verify_interop",
                              "PQClean vs liboqs verdict disagree (dir B)");
        }
    }
    printf("[pqc-diff] %s sign/verify interop: %ld iters, both directions agree\n", MLDSA, iters);
    free(pk); free(sk); free(sig);
}

int main(int argc, char **argv) {
    long iters = (argc > 1) ? atol(argv[1]) : 2000;
    unsigned seed = (argc > 2) ? (unsigned)atol(argv[2]) : 42;
    srand(seed);
    OQS_init();

    OQS_KEM *k = OQS_KEM_new(MLKEM);
    if (!k) { fprintf(stderr, "CMF: liboqs KEM %s not enabled\n", MLKEM); return 1; }
    OQS_SIG *s = OQS_SIG_new(MLDSA);
    if (!s) { fprintf(stderr, "CMF: liboqs SIG %s not enabled\n", MLDSA); return 1; }

    kem_interop(k, iters);
    sig_interop(s, iters);

    OQS_KEM_free(k);
    OQS_SIG_free(s);
    printf("[pqc-diff] all liboqs<->PQClean differentials agree\n");
    return 0;
}
