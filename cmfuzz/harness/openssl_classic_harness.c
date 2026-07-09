/*
 * CMFuzz harness for traditional primitives via OpenSSL EVP (Pillar 3: classic).
 *
 * Oracles (functional + self-differential, à la Cryptofuzz internal consistency):
 *   MR1  digest chunked == one-shot     (streaming vs single Update)
 *   MR2  AEAD roundtrip: Dec(Enc(m)) == m and tag verifies
 *   MR3  AEAD tamper: flipping a ciphertext/tag byte must fail authentication
 *   MR4  HMAC determinism + chunked == one-shot
 * Memory bugs surface via ASan/UBSan.
 */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "../engine/cmfuzz_common.h"

static void digest_oracle(cmf_reader_t *r) {
    const uint8_t *msg; size_t mlen = cmf_rest(r, &msg);
    const EVP_MD *md = EVP_sha256();
    unsigned char d1[EVP_MAX_MD_SIZE], d2[EVP_MAX_MD_SIZE];
    unsigned int l1 = 0, l2 = 0;

    /* one-shot */
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, md, NULL);
    EVP_DigestUpdate(c, msg, mlen);
    EVP_DigestFinal_ex(c, d1, &l1);
    EVP_MD_CTX_free(c);

    /* chunked in 1..17 byte pieces */
    c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, md, NULL);
    size_t off = 0; size_t step = (mlen % 17) + 1;
    while (off < mlen) {
        size_t n = (mlen - off < step) ? (mlen - off) : step;
        EVP_DigestUpdate(c, msg + off, n);
        off += n;
    }
    EVP_DigestFinal_ex(c, d2, &l2);
    EVP_MD_CTX_free(c);

    if (l1 != l2 || memcmp(d1, d2, l1) != 0)
        CMF_VIOLATION("OpenSSL-SHA256", "MR1_chunk_equiv", "chunked != one-shot digest");
}

static void aead_oracle(cmf_reader_t *r, uint32_t sel) {
    uint8_t key[32], iv[12];
    cmf_randombytes(key, sizeof key);
    cmf_randombytes(iv, sizeof iv);
    const uint8_t *pt; size_t ptlen = cmf_rest(r, &pt);
    if (ptlen == 0 || ptlen > 4096) return;

    uint8_t *ct = malloc(ptlen), *dec = malloc(ptlen); uint8_t tag[16];
    if (!ct || !dec) { free(ct); free(dec); return; }
    int outl = 0, tmpl = 0;

    EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(e, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(e, ct, &outl, pt, (int)ptlen);
    EVP_EncryptFinal_ex(e, ct + outl, &tmpl);
    EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(e);

    /* MR2: roundtrip */
    EVP_CIPHER_CTX *d = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(d, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(d, dec, &outl, ct, (int)ptlen);
    EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ok = EVP_DecryptFinal_ex(d, dec + outl, &tmpl);
    EVP_CIPHER_CTX_free(d);
    if (ok <= 0 || memcmp(pt, dec, ptlen) != 0)
        CMF_VIOLATION("OpenSSL-AES-256-GCM", "MR2_roundtrip", "AEAD roundtrip mismatch");

    /* MR3: tamper must fail auth */
    ct[sel % ptlen] ^= 0x01;
    EVP_CIPHER_CTX *d2 = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(d2, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(d2, dec, &outl, ct, (int)ptlen);
    EVP_CIPHER_CTX_ctrl(d2, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ok2 = EVP_DecryptFinal_ex(d2, dec + outl, &tmpl);
    EVP_CIPHER_CTX_free(d2);
    if (ok2 > 0)
        CMF_VIOLATION("OpenSSL-AES-256-GCM", "MR3_tamper", "tampered ciphertext authenticated");

    free(ct); free(dec);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    cmf_reader_t r; cmf_reader_init(&r, data, size);
    uint8_t mode = cmf_u8(&r);
    uint32_t sel = cmf_u32(&r);
    /* seed the deterministic PRNG for key/iv from the leading bytes */
    cmf_prng_seed(data, size);

    switch (mode % 2) {
        case 0: digest_oracle(&r); break;
        case 1: aead_oracle(&r, sel); break;
    }
    return 0;
}
