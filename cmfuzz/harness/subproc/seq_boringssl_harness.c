/*
 * CMFuzz L3 (sequence / API-misuse) harness — BoringSSL EVP_AEAD state machine.
 *
 * BoringSSL deliberately drops OpenSSL's EVP_CIPHER AEAD update loop in favour
 * of the one-shot EVP_AEAD API (EVP_AEAD_CTX_seal / _open). That different
 * state machine has its own misuse hazards, exercised here so stage 2.1's new
 * library carries its own L3 target (per PLAN 2.1). Links ONLY BoringSSL.
 *
 *  mode 0  Nonce uniqueness (AES-256-GCM via EVP_AEAD)
 *          GCM is a CTR-mode stream cipher: sealing two messages under the same
 *          (key, nonce) leaks their XOR (ct1^ct2 == m1^m2 over the message
 *          bytes) and destroys authentication. A correct nonce source yields a
 *          fresh nonce per message; a reused one is catastrophic.
 *          O6-nonce-uniqueness : detect ct1^ct2 == m1^m2 under an identical nonce.
 *
 *  mode 1  Release-before-verify (EVP_AEAD open state machine)
 *          EVP_AEAD_CTX_open() authenticates and decrypts in one shot: it
 *          returns 0 (and yields NO trustworthy plaintext) on a forged/tampered
 *          input. The contract is to use the output only when open() returns 1.
 *          O6-release-before-verify : delivering plaintext for a tampered
 *          ciphertext (i.e. when open() failed) is a violation.
 *
 * Faults:
 *   CMF_FAULT_NONCE=1   : nonce source returns a constant -> O6-nonce-uniqueness.
 *   CMF_FAULT_RELEASE=1 : output used regardless of open()'s result ->
 *                         O6-release-before-verify fires.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/aead.h>
#include "../../engine/cmfuzz_common.h"

#define ALG "AES-256-GCM/boringssl-seq"
#define NONCELEN 12
#define TAGLEN   16

static void nonce_source(uint8_t n[NONCELEN]) {
#ifdef CMF_FAULT_NONCE
    memset(n, 0, NONCELEN);                    /* fault: reused/predictable nonce */
#else
    cmf_randombytes(n, NONCELEN);
#endif
}

static int seal(const uint8_t k[32], const uint8_t n[NONCELEN], const uint8_t *m,
                size_t mn, uint8_t *out) {
    EVP_AEAD_CTX *c = EVP_AEAD_CTX_new(EVP_aead_aes_256_gcm(), k, 32,
                                       EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (!c) return -1;
    size_t ol = 0;
    int ok = EVP_AEAD_CTX_seal(c, out, &ol, mn + TAGLEN, n, NONCELEN, m, mn, NULL, 0);
    EVP_AEAD_CTX_free(c);
    return ok ? (int)ol : -1;
}

static void test_nonce(cmf_reader_t *r) {
    uint8_t k[32]; cmf_randombytes(k, 32);
    const uint8_t *m; size_t mn = cmf_rest(r, &m);
    if (mn < 2) return; if (mn > 256) mn = 256;
    /* two DISTINCT messages of equal length */
    uint8_t m1[256], m2[256];
    memcpy(m1, m, mn); memcpy(m2, m, mn); m2[0] ^= 0xFF;
    uint8_t n1[NONCELEN], n2[NONCELEN], c1[256 + TAGLEN], c2[256 + TAGLEN];
    nonce_source(n1); int l1 = seal(k, n1, m1, mn, c1);
    nonce_source(n2); int l2 = seal(k, n2, m2, mn, c2);
    if (l1 < 0 || l2 < 0) return;
    /* keystream reuse: identical nonce -> ct1^ct2 recovers m1^m2 over the msg */
    if (memcmp(n1, n2, NONCELEN) == 0) {
        int leak = 1;
        for (size_t i = 0; i < mn; i++)
            if ((c1[i] ^ c2[i]) != (m1[i] ^ m2[i])) { leak = 0; break; }
        CMF_ASSERT(!leak, ALG, "O6-nonce-uniqueness",
                   "identical nonce reused: ct1^ct2 == m1^m2 (GCM keystream reuse)");
    }
}

static void test_open(cmf_reader_t *r) {
    uint8_t k[32], n[NONCELEN]; cmf_randombytes(k, 32); cmf_randombytes(n, NONCELEN);
    int tamper = cmf_u8(r) & 1;                /* forge? read BEFORE consuming rest */
    const uint8_t *m; size_t mn = cmf_rest(r, &m);
    if (mn == 0) return; if (mn > 256) mn = 256;
    uint8_t ct[256 + TAGLEN], pt[256 + TAGLEN]; size_t cl = 0, pl = 0;
    EVP_AEAD_CTX *c = EVP_AEAD_CTX_new(EVP_aead_aes_256_gcm(), k, 32,
                                       EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (!c) return;
    if (!EVP_AEAD_CTX_seal(c, ct, &cl, mn + TAGLEN, n, NONCELEN, m, mn, NULL, 0)) {
        EVP_AEAD_CTX_free(c); return;
    }
    if (tamper) ct[0] ^= 0x01;                 /* forge the ciphertext */
    int openOk = EVP_AEAD_CTX_open(c, pt, &pl, sizeof pt, n, NONCELEN, ct, cl, NULL, 0);
    EVP_AEAD_CTX_free(c);
#ifdef CMF_FAULT_RELEASE
    int deliver = 1;                           /* bug: use output regardless of open() */
#else
    int deliver = openOk;                      /* contract: only after successful open */
#endif
    CMF_ASSERT(!(deliver && tamper), ALG, "O6-release-before-verify",
               "EVP_AEAD plaintext used without a successful open() (forgery accepted)");
    if (deliver && !tamper)                    /* authentic path must round-trip */
        CMF_ASSERT(pl == mn && memcmp(pt, m, mn) == 0, ALG, "O6-release-before-verify",
                   "verified plaintext != message");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    cmf_prng_seed(data, size);
    cmf_reader_t r; cmf_reader_init(&r, data, size);
    uint8_t mode = cmf_u8(&r);
#ifdef CMF_FAULT_NONCE
    test_nonce(&r); return 0;
#endif
#ifdef CMF_FAULT_RELEASE
    test_open(&r); return 0;
#endif
    if (mode & 1) test_open(&r);
    else          test_nonce(&r);
    return 0;
}
