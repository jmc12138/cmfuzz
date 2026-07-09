/*
 * CMFuzz L3 (sequence / API-misuse) harness — PQC KEM key-confusion contract (O6).
 *
 * A common API misuse in a session is mixing up key material: encapsulating to
 * one keypair but decapsulating with another party's secret key. A safe KEM
 * (ML-KEM has implicit rejection) must then NOT produce a matching shared
 * secret — the session must fail closed, never falsely agree.
 *
 * Sequence modelled per input:
 *   keygen(A); keygen(B);
 *   (ct, ss_enc) = encaps(pk_A);          // sender targets Alice
 *   ss_dec       = decaps(ct, sk_B);      // MISUSE: Bob's key
 *   contract O6-kem-key-confusion : ss_dec != ss_enc  (no false agreement)
 * plus the honest path ss = decaps(ct, sk_A) must equal ss_enc (O6-kem-roundtrip).
 *
 * Fault:
 *   CMF_FAULT_KEMSWAP=1 : a buggy result cache aliases the encapsulator's secret
 *   into the (wrong-key) decapsulation -> O6-kem-key-confusion fires.
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <oqs/oqs.h>
#include "../engine/cmfuzz_common.h"

#ifndef CMF_PQC_KEM
#define CMF_PQC_KEM OQS_KEM_alg_ml_kem_768
#endif
#define ALG "ML-KEM-768/seq"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    cmf_prng_seed(data, size);

    OQS_KEM *kem = OQS_KEM_new(CMF_PQC_KEM);
    if (!kem) return 0;

    uint8_t *pkA = malloc(kem->length_public_key), *skA = malloc(kem->length_secret_key);
    uint8_t *pkB = malloc(kem->length_public_key), *skB = malloc(kem->length_secret_key);
    uint8_t *ct  = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_A   = malloc(kem->length_shared_secret);
    uint8_t *ss_B   = malloc(kem->length_shared_secret);

    if (OQS_KEM_keypair(kem, pkA, skA) == OQS_SUCCESS &&
        OQS_KEM_keypair(kem, pkB, skB) == OQS_SUCCESS &&
        OQS_KEM_encaps(kem, ct, ss_enc, pkA) == OQS_SUCCESS) {

        /* honest decapsulation with the correct key must agree */
        if (OQS_KEM_decaps(kem, ss_A, ct, skA) == OQS_SUCCESS)
            CMF_ASSERT(memcmp(ss_A, ss_enc, kem->length_shared_secret) == 0, ALG,
                       "O6-kem-roundtrip", "honest KEM decapsulation did not agree");

        /* MISUSE: decapsulate with the WRONG party's secret key */
        if (OQS_KEM_decaps(kem, ss_B, ct, skB) == OQS_SUCCESS) {
#ifdef CMF_FAULT_KEMSWAP
            memcpy(ss_B, ss_enc, kem->length_shared_secret); /* bug: aliased result cache */
#endif
            CMF_ASSERT(memcmp(ss_B, ss_enc, kem->length_shared_secret) != 0, ALG,
                       "O6-kem-key-confusion",
                       "wrong-key decapsulation falsely agreed with sender");
        }
    }

    free(pkA); free(skA); free(pkB); free(skB);
    free(ct); free(ss_enc); free(ss_A); free(ss_B);
    OQS_KEM_free(kem);
    return 0;
}
