/*
 * CMFuzz harness for liboqs KEMs (Pillar 3: PQC / KEM).
 *
 * Structure-aware, spec-driven, metamorphic-oracle-embedded libFuzzer target.
 * The algorithm under test is selected at compile time via -DCMF_KEM_ALG="...".
 *
 * Fuzzer input layout (structure-aware):
 *   [0]        : mode/flag byte
 *   [1..4]     : mutation offset selector (for malleability)
 *   [5..]      : entropy stream (seeds keygen+encaps) and, in MEM mode, the
 *                attacker-controlled ciphertext bytes fed straight into decaps.
 *
 * Oracles:
 *   MR1  correctness: Decaps(sk, Encaps(pk).c) == Encaps(pk).ss
 *   MR2  ciphertext non-malleability: Decaps(sk, mutate(c)) != honest ss
 *   MR3  wrong-key separation: Decaps(sk2, c) != ss              (sk2 != sk)
 *   MR4  decaps determinism: Decaps(sk, c) stable across calls
 *   MEM  memory safety: Decaps(sk, attacker_bytes) must not corrupt memory
 *        (violations surface via ASan/UBSan, mirroring CVE-2026-46344-class bugs)
 */
#include <oqs/oqs.h>
#include "../engine/cmfuzz_common.h"

#ifndef CMF_KEM_ALG
#define CMF_KEM_ALG "ML-KEM-768"
#endif

extern void OQS_randombytes_custom_algorithm(void (*)(uint8_t *, size_t));

static OQS_KEM *g_kem = NULL;

static void ensure_init(void) {
    if (g_kem) return;
    OQS_init();
    OQS_randombytes_custom_algorithm(cmf_randombytes);
    g_kem = OQS_KEM_new(CMF_KEM_ALG);
    if (!g_kem) { fprintf(stderr, "CMF: KEM %s not enabled\n", CMF_KEM_ALG); exit(0); }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ensure_init();
    if (size < 8) return 0;

    cmf_reader_t r; cmf_reader_init(&r, data, size);
    uint8_t mode = cmf_u8(&r);
    uint32_t sel = cmf_u32(&r);
    /* seed deterministic RNG from the remaining bytes */
    const uint8_t *tail; size_t tail_len = cmf_rest(&r, &tail);
    cmf_prng_seed(tail, tail_len);

    OQS_KEM *k = g_kem;
    uint8_t *pk  = malloc(k->length_public_key);
    uint8_t *sk  = malloc(k->length_secret_key);
    uint8_t *pk2 = malloc(k->length_public_key);
    uint8_t *sk2 = malloc(k->length_secret_key);
    uint8_t *ct  = malloc(k->length_ciphertext);
    uint8_t *ss_e = malloc(k->length_shared_secret);
    uint8_t *ss_d = malloc(k->length_shared_secret);
    uint8_t *ss_d2 = malloc(k->length_shared_secret);

    if (!pk||!sk||!pk2||!sk2||!ct||!ss_e||!ss_d||!ss_d2) goto done;

    if (k->keypair(pk, sk) != OQS_SUCCESS) goto done;
    if (k->encaps(ct, ss_e, pk) != OQS_SUCCESS) goto done;

    /* MR1: correctness round-trip */
    if (k->decaps(ss_d, ct, sk) != OQS_SUCCESS)
        CMF_VIOLATION(CMF_KEM_ALG, "MR1_decaps_status", "decaps failed on honest ct");
#ifdef CMF_FAULT_MR1
    /* self-test hook: corrupt the recovered secret so MR1 must fire */
    ss_d[0] ^= 0xFF;
#endif
    if (memcmp(ss_e, ss_d, k->length_shared_secret) != 0)
        CMF_VIOLATION(CMF_KEM_ALG, "MR1_correctness", "shared secrets differ");

    /* MR4: decaps determinism */
    if (k->decaps(ss_d2, ct, sk) == OQS_SUCCESS &&
        memcmp(ss_d, ss_d2, k->length_shared_secret) != 0)
        CMF_VIOLATION(CMF_KEM_ALG, "MR4_determinism", "decaps not deterministic");

    if (mode & 0x01) {
        /* MR2: ciphertext non-malleability. Flip one bit at a fuzzer-chosen spot. */
        uint8_t *ctm = malloc(k->length_ciphertext);
        if (ctm) {
            memcpy(ctm, ct, k->length_ciphertext);
            size_t off = sel % k->length_ciphertext;
            ctm[off] ^= (uint8_t)(1u << (sel & 7));
            if (k->decaps(ss_d2, ctm, sk) == OQS_SUCCESS &&
                memcmp(ss_d2, ss_e, k->length_shared_secret) == 0)
                CMF_VIOLATION(CMF_KEM_ALG, "MR2_malleability",
                              "mutated ct yields honest shared secret");
            free(ctm);
        }
    }

    if (mode & 0x02) {
        /* MR3: independent keypair must not recover ss from c. */
        if (k->keypair(pk2, sk2) == OQS_SUCCESS &&
            k->decaps(ss_d2, ct, sk2) == OQS_SUCCESS &&
            memcmp(ss_d2, ss_e, k->length_shared_secret) == 0)
            CMF_VIOLATION(CMF_KEM_ALG, "MR3_wrong_key",
                          "foreign sk recovers honest shared secret");
    }

    if (mode & 0x04) {
        /* MEM: feed attacker-controlled bytes as ciphertext into decaps.
         * No logical oracle here; ASan/UBSan catch parsing memory bugs. */
        size_t n = tail_len < k->length_ciphertext ? tail_len : k->length_ciphertext;
        memcpy(ct, tail, n);
        (void)k->decaps(ss_d2, ct, sk);
    }

done:
    free(pk); free(sk); free(pk2); free(sk2);
    free(ct); free(ss_e); free(ss_d); free(ss_d2);
    return 0;
}
