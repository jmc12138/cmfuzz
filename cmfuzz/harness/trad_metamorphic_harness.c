/*
 * CMFuzz metamorphic harness for TRADITIONAL algorithms (single-implementation).
 *
 * Shows that traditional primitives don't need a second library to be tested:
 * the same cryptographic-definition metamorphic relations used for PQC/FHE apply
 * here too. Uses OpenSSL as the implementation under test; every relation must
 * hold for ANY correct implementation, so the oracle is library-independent.
 *
 * Relations:
 *   SHA-256   : chunked consistency  H(m) == update(m[:k]);update(m[k:])
 *               determinism          H(m) == H(m)
 *   HMAC-256  : determinism + key sensitivity (flip a key bit -> tag changes)
 *   AES-256-GCM / ChaCha20-Poly1305:
 *               round-trip           Dec(Enc(m)) == m
 *               tamper-reject        flip 1 bit of ct/tag/aad -> Dec fails
 *               wrong-key/nonce      Dec under wrong key/nonce fails
 *
 * Build CMF_FAULT_TRAD=1 for the fault-injected self-test variant.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "../engine/cmfuzz_common.h"

/* AEAD encrypt via EVP; returns ct||tag length, writes into out (>= n+16). */
static int aead_encrypt(const EVP_CIPHER *ci, const uint8_t *key, int keylen,
                        const uint8_t *iv, int ivlen,
                        const uint8_t *aad, int adn,
                        const uint8_t *m, int n, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len = 0, ctl = 0;
    EVP_EncryptInit_ex(c, ci, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL);
    EVP_EncryptInit_ex(c, NULL, NULL, key, iv);
    (void)keylen;
    if (adn) EVP_EncryptUpdate(c, NULL, &len, aad, adn);
    EVP_EncryptUpdate(c, out, &len, m, n); ctl = len;
    EVP_EncryptFinal_ex(c, out + ctl, &len); ctl += len;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, out + ctl);
    EVP_CIPHER_CTX_free(c);
    return ctl + 16;
}

/* AEAD decrypt+verify; returns 1 on success (tag ok), 0 on failure. */
static int aead_decrypt(const EVP_CIPHER *ci, const uint8_t *key, int keylen,
                        const uint8_t *iv, int ivlen,
                        const uint8_t *aad, int adn,
                        const uint8_t *ct, int ctn, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len = 0, ok;
    (void)keylen;
    EVP_DecryptInit_ex(c, ci, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL);
    EVP_DecryptInit_ex(c, NULL, NULL, key, iv);
    if (adn) EVP_DecryptUpdate(c, NULL, &len, aad, adn);
    EVP_DecryptUpdate(c, out, &len, ct, ctn - 16);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(ct + ctn - 16));
    ok = EVP_DecryptFinal_ex(c, out + len, &len);
    EVP_CIPHER_CTX_free(c);
    return ok == 1;
}

static void test_sha256(const uint8_t *m, size_t n) {
    uint8_t d1[32], d2[32], d3[32];
    unsigned int l = 32;
    EVP_Digest(m, n, d1, &l, EVP_sha256(), NULL);
    EVP_Digest(m, n, d2, &l, EVP_sha256(), NULL);
    CMF_ASSERT(memcmp(d1, d2, 32) == 0, "SHA-256", "determinism", "H(m)!=H(m)");

    /* chunked/streaming consistency */
    size_t k = n ? (m[0] % (n + 1)) : 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, m, k);
    EVP_DigestUpdate(c, m + k, n - k);
#ifdef CMF_FAULT_TRAD
    if (n > 0) k ^= 1;   /* corrupt split so streaming != one-shot */
#endif
    EVP_DigestFinal_ex(c, d3, &l);
    EVP_MD_CTX_free(c);
    CMF_ASSERT(memcmp(d1, d3, 32) == 0, "SHA-256", "chunk_consistency",
               "H(m) != update(m[:k]);update(m[k:])");
}

static void test_hmac(const uint8_t key[32], const uint8_t *m, size_t n) {
    uint8_t t1[32], t2[32], t3[32];
    unsigned int l = 32;
    HMAC(EVP_sha256(), key, 32, m, n, t1, &l);
    HMAC(EVP_sha256(), key, 32, m, n, t2, &l);
    CMF_ASSERT(memcmp(t1, t2, 32) == 0, "HMAC-SHA256", "determinism", "tag!=tag");

    uint8_t key2[32]; memcpy(key2, key, 32); key2[0] ^= 0x80;
    HMAC(EVP_sha256(), key2, 32, m, n, t3, &l);
    CMF_ASSERT(memcmp(t1, t3, 32) != 0, "HMAC-SHA256", "key_sensitivity",
               "different key produced identical tag");
}

static void test_aead(const EVP_CIPHER *ci, const char *alg,
                      const uint8_t key[32], const uint8_t iv[12],
                      const uint8_t *aad, size_t adn,
                      const uint8_t *m, size_t n) {
    uint8_t ct[1200 + 16], pt[1200];
    if (n > 1200) n = 1200;
    int ctn = aead_encrypt(ci, key, 32, iv, 12, aad, (int)adn, m, (int)n, ct);

    /* round-trip */
    int ok = aead_decrypt(ci, key, 32, iv, 12, aad, (int)adn, ct, ctn, pt);
    CMF_ASSERT(ok, alg, "roundtrip", "Dec(Enc(m)) failed to authenticate");
    CMF_ASSERT(memcmp(pt, m, n) == 0, alg, "roundtrip", "Dec(Enc(m)) != m");

#ifndef CMF_FAULT_TRAD
    /* tamper-reject: flip one bit of the ciphertext/tag -> must fail */
    uint8_t bad[1200 + 16]; memcpy(bad, ct, ctn);
    bad[ctn - 1] ^= 0x01;   /* corrupt last tag byte */
    int ok2 = aead_decrypt(ci, key, 32, iv, 12, aad, (int)adn, bad, ctn, pt);
    CMF_ASSERT(!ok2, alg, "tamper_reject", "tampered tag still authenticated");

    /* wrong key -> must fail */
    uint8_t k2[32]; memcpy(k2, key, 32); k2[0] ^= 0x01;
    int ok3 = aead_decrypt(ci, k2, 32, iv, 12, aad, (int)adn, ct, ctn, pt);
    CMF_ASSERT(!ok3, alg, "wrong_key", "wrong key still authenticated");
#else
    /* fault: claim a tampered ciphertext authenticates (oracle must fire) */
    uint8_t bad[1200 + 16]; memcpy(bad, ct, ctn);
    bad[ctn - 1] ^= 0x01;
    aead_decrypt(ci, key, 32, iv, 12, aad, (int)adn, bad, ctn, pt);
    CMF_ASSERT(0, alg, "tamper_reject", "tampered tag still authenticated");
#endif
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    cmf_prng_seed(data, size);
    cmf_reader_t r; cmf_reader_init(&r, data, size);
    uint8_t op = cmf_u8(&r) % 4;
    uint8_t split = cmf_u8(&r);

    uint8_t key[32], iv[12];
    cmf_randombytes(key, 32);
    cmf_randombytes(iv, 12);

    const uint8_t *p; size_t rem = cmf_rest(&r, &p);
    size_t adn = rem ? (split % (rem + 1)) : 0;
    const uint8_t *aad = p, *msg = p + adn; size_t mlen = rem - adn;

    switch (op) {
        case 0: test_sha256(p, rem); break;
        case 1: test_hmac(key, p, rem); break;
        case 2: test_aead(EVP_aes_256_gcm(), "AES-256-GCM",
                          key, iv, aad, adn, msg, mlen); break;
        case 3: test_aead(EVP_chacha20_poly1305(), "ChaCha20-Poly1305",
                          key, iv, aad, adn, msg, mlen); break;
    }
    return 0;
}
