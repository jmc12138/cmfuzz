/*
 * CMFuzz L3 (sequence / API-misuse) harness — EVP cipher state-machine +
 * CBC IV-unpredictability contracts (O6). Complements seq_aead_harness.c
 * (which covers AEAD nonce-uniqueness + release-before-verify).
 *
 *  mode 0  CBC IV unpredictability
 *          CBC-mode confidentiality requires a fresh, unpredictable IV per
 *          message: with a random IV, encrypting the SAME plaintext twice must
 *          yield DIFFERENT ciphertext. A fixed/predictable IV makes the two
 *          ciphertexts identical, leaking plaintext equality (a real class of
 *          bug, cf. TLS1.0 predictable-IV / BEAST).
 *          O6-iv-unpredictability : same plaintext under the IV source must not
 *          produce identical ciphertext.
 *
 *  mode 1  EVP context lifecycle (use-after-free)
 *          The EVP_CIPHER_CTX contract forbids touching a context after
 *          EVP_CIPHER_CTX_free(). Correct sequences stop after free; the fault
 *          drives EVP_EncryptUpdate() on the freed context — a heap
 *          use-after-free caught by ASan (O4 memory-safety integrated into the
 *          L3 sequence layer).
 *
 * Faults:
 *   CMF_FAULT_IV=1  : IV source returns a constant -> O6-iv-unpredictability fires.
 *   CMF_FAULT_UAF=1 : use the EVP context after free -> ASan heap-use-after-free.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include "../engine/cmfuzz_common.h"

#define ALG "AES-256-CBC/seq"

/* Per-message IV source. Correct: fresh random IV. Fault: constant IV. */
static void iv_source(uint8_t iv[16]) {
#ifdef CMF_FAULT_IV
    memset(iv, 0, 16);                        /* fault: fixed/predictable IV */
#else
    cmf_randombytes(iv, 16);
#endif
}

static int cbc_enc(const uint8_t k[32], const uint8_t iv[16], const uint8_t *m,
                   int mn, uint8_t *ct) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, cn = 0;
    EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), NULL, k, iv);
    EVP_EncryptUpdate(c, ct, &l, m, mn); cn = l;
    EVP_EncryptFinal_ex(c, ct + cn, &l); cn += l;
    EVP_CIPHER_CTX_free(c);
    return cn;
}

static void test_iv(cmf_reader_t *r) {
    uint8_t k[32]; cmf_randombytes(k, 32);
    const uint8_t *m; size_t mn = cmf_rest(r, &m);
    if (mn == 0) return; if (mn > 256) mn = 256;
    uint8_t iv1[16], iv2[16], c1[256 + 16], c2[256 + 16];
    iv_source(iv1); int n1 = cbc_enc(k, iv1, m, (int)mn, c1);
    iv_source(iv2); int n2 = cbc_enc(k, iv2, m, (int)mn, c2);
    /* Same plaintext, same key: distinct fresh IVs must diverge the ciphertext. */
    int same = (n1 == n2) && memcmp(c1, c2, (size_t)n1) == 0;
    CMF_ASSERT(!same, ALG, "O6-iv-unpredictability",
               "identical ciphertext for identical plaintext (predictable/reused IV)");
}

static void test_ctx_lifecycle(cmf_reader_t *r) {
    uint8_t k[32], iv[16]; cmf_randombytes(k, 32); cmf_randombytes(iv, 16);
    const uint8_t *m; size_t mn = cmf_rest(r, &m);
    if (mn == 0) return; if (mn > 256) mn = 256;
    uint8_t ct[256 + 16]; int l = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), NULL, k, iv);
    EVP_EncryptUpdate(c, ct, &l, m, (int)mn);
    EVP_CIPHER_CTX_free(c);
#ifdef CMF_FAULT_UAF
    /* Contract violation: touch the context after free -> heap-use-after-free. */
    EVP_EncryptUpdate(c, ct, &l, m, (int)mn);
    CMF_VIOLATION(ALG, "O6-ctx-use-after-free",
                  "EVP context used after EVP_CIPHER_CTX_free()");
#endif
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    cmf_prng_seed(data, size);
    cmf_reader_t r; cmf_reader_init(&r, data, size);
    uint8_t mode = cmf_u8(&r);
#ifdef CMF_FAULT_IV
    test_iv(&r); return 0;
#endif
#ifdef CMF_FAULT_UAF
    test_ctx_lifecycle(&r); return 0;
#endif
    if (mode & 1) test_ctx_lifecycle(&r);
    else          test_iv(&r);
    return 0;
}
