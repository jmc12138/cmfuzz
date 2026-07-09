/*
 * CMFuzz harness for liboqs signature schemes (Pillar 3: PQC / DSS).
 * Algorithm selected at compile time via -DCMF_SIG_ALG="...".
 *
 * Oracles:
 *   MR1  correctness:  Verify(pk, m, Sign(sk,m)) == 1
 *   MR2  message-binding (EUF): Verify(pk, m', sig) == 0 for m' != m
 *   MR3  signature non-malleability (SUF): Verify(pk, m, mutate(sig)) == 0
 *        (this is exactly the property CIFT found violated by Falcon's
 *         compressed format; a violation here flags a SUF weakness/bug)
 *   MR4  wrong-key: Verify(pk2, m, sig) == 0
 *   MEM  memory safety: Verify on attacker-controlled sig/message
 */
#include <oqs/oqs.h>
#include "../engine/cmfuzz_common.h"

#ifndef CMF_SIG_ALG
#define CMF_SIG_ALG "ML-DSA-65"
#endif

extern void OQS_randombytes_custom_algorithm(void (*)(uint8_t *, size_t));

static OQS_SIG *g_sig = NULL;

static void ensure_init(void) {
    if (g_sig) return;
    OQS_init();
    OQS_randombytes_custom_algorithm(cmf_randombytes);
    g_sig = OQS_SIG_new(CMF_SIG_ALG);
    if (!g_sig) { fprintf(stderr, "CMF: SIG %s not enabled\n", CMF_SIG_ALG); exit(0); }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ensure_init();
    if (size < 8) return 0;

    cmf_reader_t r; cmf_reader_init(&r, data, size);
    uint8_t mode = cmf_u8(&r);
    uint32_t sel = cmf_u32(&r);
    const uint8_t *tail; size_t tail_len = cmf_rest(&r, &tail);
    cmf_prng_seed(tail, tail_len);

    OQS_SIG *s = g_sig;
    uint8_t *pk  = malloc(s->length_public_key);
    uint8_t *sk  = malloc(s->length_secret_key);
    uint8_t *pk2 = malloc(s->length_public_key);
    uint8_t *sk2 = malloc(s->length_secret_key);
    uint8_t *sig = malloc(s->length_signature);
    size_t siglen = 0;

    /* message derived from the tail so it co-varies with the fuzzer input */
    size_t mlen = tail_len ? (tail_len % 256) + 1 : 1;
    uint8_t *msg = malloc(mlen);
    if (!pk||!sk||!pk2||!sk2||!sig||!msg) goto done;
    for (size_t i = 0; i < mlen; i++) msg[i] = tail_len ? tail[i % tail_len] : 0;

    if (s->keypair(pk, sk) != OQS_SUCCESS) goto done;
    if (s->sign(sig, &siglen, msg, mlen, sk) != OQS_SUCCESS) goto done;

    /* MR1: correctness */
    if (s->verify(msg, mlen, sig, siglen, pk) != OQS_SUCCESS)
        CMF_VIOLATION(CMF_SIG_ALG, "MR1_correctness", "valid signature rejected");
#ifdef CMF_FAULT_MR3
    /* self-test hook: emulate a SUF-broken verifier that ignores byte 0 of the
     * signature, so a mutated signature still verifies. This exercises the MR3
     * detection+abort path against a *simulated* buggy implementation. */
    if (siglen > 0) {
        uint8_t saved = sig[0];
        sig[0] ^= 0x01;                       /* mutate the signature */
        sig[0] = saved;                       /* buggy verifier "ignores" byte 0 */
        if (s->verify(msg, mlen, sig, siglen, pk) == OQS_SUCCESS)
            CMF_VIOLATION(CMF_SIG_ALG, "MR3_strong_unforgeability",
                          "mutated signature still verifies (SUF violation)");
    }
#endif

    if ((mode & 0x01) && mlen > 1) {
        /* MR2: message-binding. Flip a message byte; signature must not verify. */
        uint8_t *m2 = malloc(mlen);
        if (m2) {
            memcpy(m2, msg, mlen);
            m2[sel % mlen] ^= 0x01;
            if (s->verify(m2, mlen, sig, siglen, pk) == OQS_SUCCESS)
                CMF_VIOLATION(CMF_SIG_ALG, "MR2_message_binding",
                              "signature verifies for altered message");
            free(m2);
        }
    }

    if ((mode & 0x02) && siglen > 0) {
        /* MR3: strong unforgeability. Mutate the signature; must not verify. */
        uint8_t *sg = malloc(siglen);
        if (sg) {
            memcpy(sg, sig, siglen);
            size_t off = sel % siglen;
            sg[off] ^= (uint8_t)(1u << (sel & 7));
            if (memcmp(sg, sig, siglen) != 0 &&
                s->verify(msg, mlen, sg, siglen, pk) == OQS_SUCCESS)
                CMF_VIOLATION(CMF_SIG_ALG, "MR3_strong_unforgeability",
                              "mutated signature still verifies (SUF violation)");
            free(sg);
        }
    }

    if (mode & 0x04) {
        /* MR4: wrong key. */
        if (s->keypair(pk2, sk2) == OQS_SUCCESS &&
            s->verify(msg, mlen, sig, siglen, pk2) == OQS_SUCCESS)
            CMF_VIOLATION(CMF_SIG_ALG, "MR4_wrong_key",
                          "signature verifies under foreign public key");
    }

    if (mode & 0x08) {
        /* MEM: attacker-controlled signature bytes into verify. */
        size_t n = tail_len < s->length_signature ? tail_len : s->length_signature;
        memcpy(sig, tail, n);
        (void)s->verify(msg, mlen, sig, n, pk);
    }

done:
    free(pk); free(sk); free(pk2); free(sk2); free(sig); free(msg);
    return 0;
}
