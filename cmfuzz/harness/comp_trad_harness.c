/*
 * CMFuzz L2 (composition) harness — traditional generic composition.
 *
 * Two standard traditional compositions, selected per-input:
 *
 *  mode 0  Encrypt-then-MAC (EtM): the provably-secure generic composition.
 *          seal:  ct = AES-256-CBC_{k1}(m); tag = HMAC-SHA256_{k2}(iv||ct)
 *          open:  verify tag over (iv||ct) FIRST; only then CBC-decrypt.
 *          O5-roundtrip           : open(seal(m)) == m
 *          O5-ciphertext-integrity: flip any bit of iv/ct/tag -> open MUST reject
 *                                   (this is exactly what EtM buys you; a broken
 *                                    composition that decrypts-then-checks, or skips
 *                                    the MAC, would accept the forgery).
 *
 *  mode 1  TLS1.3-style record layer: AEAD (AES-256-GCM) with a per-record nonce
 *          nonce(seq) = static_iv XOR seq, and the record header as AAD.
 *          O5-roundtrip   : open(seq, seal(seq,m)) == m
 *          O5-seq-binding : open at seq' != seq -> MUST reject (nonce/ordering bound)
 *          O5-tamper      : flip ct/tag/aad -> MUST reject
 *
 * Faults:
 *   CMF_FAULT_ETM=1  : open skips the MAC check (accepts any tag) -> integrity fires
 *   CMF_FAULT_REC=1  : open ignores requested seq (uses seal's seq) -> seq-binding fires
 */
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "../engine/cmfuzz_common.h"

/* ---- Encrypt-then-MAC (AES-256-CBC + HMAC-SHA256) ------------------------ */
/* seal -> out = iv(16) || ct || tag(32); returns total len, or -1. */
static int etm_seal(const uint8_t k1[32], const uint8_t k2[32], const uint8_t iv[16],
                    const uint8_t *m, int n, uint8_t *out) {
    memcpy(out, iv, 16);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, ctn = 0;
    EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), NULL, k1, iv);
    EVP_EncryptUpdate(c, out + 16, &l, m, n); ctn = l;
    EVP_EncryptFinal_ex(c, out + 16 + ctn, &l); ctn += l;
    EVP_CIPHER_CTX_free(c);
    unsigned int tl = 32;
    HMAC(EVP_sha256(), k2, 32, out, 16 + ctn, out + 16 + ctn, &tl);  /* MAC over iv||ct */
    return 16 + ctn + 32;
}
/* open; returns plaintext length >=0 on success, -1 on reject. */
static int etm_open(const uint8_t k1[32], const uint8_t k2[32],
                    const uint8_t *in, int inlen, uint8_t *out) {
    if (inlen < 16 + 16 + 32) return -1;           /* iv + >=1 block + tag */
    int ctn = inlen - 16 - 32;
    if (ctn % 16 != 0) return -1;
    uint8_t mac[32]; unsigned int tl = 32;
    HMAC(EVP_sha256(), k2, 32, in, 16 + ctn, mac, &tl);
    int macok = CRYPTO_memcmp(mac, in + 16 + ctn, 32) == 0;
#ifdef CMF_FAULT_ETM
    macok = 1;                                     /* fault: accept any tag */
#endif
    if (!macok) return -1;                         /* EtM: reject before decrypt */
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, pn = 0, ok;
    EVP_DecryptInit_ex(c, EVP_aes_256_cbc(), NULL, k1, in);
    EVP_DecryptUpdate(c, out, &l, in + 16, ctn); pn = l;
    ok = EVP_DecryptFinal_ex(c, out + pn, &l);     /* PKCS7 pad check */
    pn += l;
    EVP_CIPHER_CTX_free(c);
    return ok == 1 ? pn : -1;
}

/* ---- TLS1.3-style record layer (AES-256-GCM, seq-derived nonce) ---------- */
static void rec_nonce(const uint8_t static_iv[12], uint64_t seq, uint8_t nonce[12]) {
    memcpy(nonce, static_iv, 12);
    for (int i = 0; i < 8; i++)                    /* XOR seq into the low 8 bytes */
        nonce[11 - i] ^= (uint8_t)(seq >> (8 * i));
}
static int rec_seal(const uint8_t key[32], const uint8_t static_iv[12], uint64_t seq,
                    const uint8_t *aad, int adn, const uint8_t *m, int n, uint8_t *out) {
    uint8_t nonce[12]; rec_nonce(static_iv, seq, nonce);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, ctn = 0;
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(c, NULL, NULL, key, nonce);
    if (adn) EVP_EncryptUpdate(c, NULL, &l, aad, adn);
    EVP_EncryptUpdate(c, out, &l, m, n); ctn = l;
    EVP_EncryptFinal_ex(c, out + ctn, &l); ctn += l;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, out + ctn);
    EVP_CIPHER_CTX_free(c);
    return ctn + 16;
}
static int rec_open(const uint8_t key[32], const uint8_t static_iv[12], uint64_t seq_req,
                    const uint8_t *aad, int adn, const uint8_t *ct, int ctn, uint8_t *out,
                    uint64_t seq_real) {
    uint64_t use = seq_req;
#ifdef CMF_FAULT_REC
    use = seq_real;                                /* fault: ignore requested seq */
#else
    (void)seq_real;
#endif
    uint8_t nonce[12]; rec_nonce(static_iv, use, nonce);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, ok;
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(c, NULL, NULL, key, nonce);
    if (adn) EVP_DecryptUpdate(c, NULL, &l, aad, adn);
    EVP_DecryptUpdate(c, out, &l, ct, ctn - 16);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(ct + ctn - 16));
    ok = EVP_DecryptFinal_ex(c, out + l, &l);
    EVP_CIPHER_CTX_free(c);
    return ok == 1;
}

static void test_etm(cmf_reader_t *r) {
    uint8_t k1[32], k2[32], iv[16];
    cmf_randombytes(k1, 32); cmf_randombytes(k2, 32); cmf_randombytes(iv, 16);
    const uint8_t *p; size_t n = cmf_rest(r, &p);
    if (n > 1024) n = 1024;
    uint8_t buf[16 + 1024 + 16 + 32], pt[1024 + 32];
    int sl = etm_seal(k1, k2, iv, p, (int)n, buf);
    int pn = etm_open(k1, k2, buf, sl, pt);
    CMF_ASSERT(pn == (int)n, "EtM(AES-CBC+HMAC)", "O5-roundtrip", "open length mismatch");
    CMF_ASSERT(pn < 0 || memcmp(pt, p, n) == 0, "EtM(AES-CBC+HMAC)", "O5-roundtrip",
               "opened plaintext != message");
    /* O5-ciphertext-integrity: flip one bit somewhere in iv||ct||tag */
    uint8_t bad[sizeof buf]; memcpy(bad, buf, sl);
    int flip = (int)(cmf_splitmix64(&g_cmf_prng.state) % (uint64_t)sl);
    bad[flip] ^= 0x01;
    int pn2 = etm_open(k1, k2, bad, sl, pt);
    CMF_ASSERT(pn2 < 0, "EtM(AES-CBC+HMAC)", "O5-ciphertext-integrity",
               "tampered ciphertext/tag was accepted");
}

static void test_record(cmf_reader_t *r) {
    uint8_t key[32], siv[12];
    cmf_randombytes(key, 32); cmf_randombytes(siv, 12);
    uint64_t seq = cmf_u32(r);
    uint8_t aad[5]; cmf_randombytes(aad, 5);       /* record header as AAD */
    const uint8_t *p; size_t n = cmf_rest(r, &p);
    if (n > 1024) n = 1024;
    uint8_t ct[1024 + 16], pt[1024 + 16];
    int ctn = rec_seal(key, siv, seq, aad, 5, p, (int)n, ct);
    /* O5-roundtrip */
    int ok = rec_open(key, siv, seq, aad, 5, ct, ctn, pt, seq);
    CMF_ASSERT(ok, "TLS1.3-record(AES-GCM)", "O5-roundtrip", "record failed to open");
    CMF_ASSERT(memcmp(pt, p, n) == 0, "TLS1.3-record(AES-GCM)", "O5-roundtrip",
               "opened plaintext != message");
    /* O5-seq-binding: open under a different sequence number must fail */
    uint64_t seq2 = seq ^ 0x1u;
    int ok2 = rec_open(key, siv, seq2, aad, 5, ct, ctn, pt, seq);
    CMF_ASSERT(!ok2, "TLS1.3-record(AES-GCM)", "O5-seq-binding",
               "record opened under wrong sequence number");
    /* O5-tamper: flip a ciphertext byte */
    uint8_t bad[sizeof ct]; memcpy(bad, ct, ctn);
    bad[(int)(cmf_splitmix64(&g_cmf_prng.state) % (uint64_t)ctn)] ^= 0x01;
    int ok3 = rec_open(key, siv, seq, aad, 5, bad, ctn, pt, seq);
    CMF_ASSERT(!ok3, "TLS1.3-record(AES-GCM)", "O5-tamper", "tampered record was accepted");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    cmf_prng_seed(data, size);
    cmf_reader_t r; cmf_reader_init(&r, data, size);
    uint8_t mode = cmf_u8(&r);
#ifdef CMF_FAULT_ETM
    test_etm(&r); return 0;
#endif
#ifdef CMF_FAULT_REC
    test_record(&r); return 0;
#endif
    if (mode & 1) test_record(&r);
    else          test_etm(&r);
    return 0;
}
