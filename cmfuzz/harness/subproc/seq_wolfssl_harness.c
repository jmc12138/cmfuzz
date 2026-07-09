/*
 * CMFuzz L3 (sequence / API-misuse) harness — wolfCrypt AES-GCM state machine.
 *
 * wolfCrypt uses a one-shot native API (wc_AesGcmSetKey + wc_AesGcmEncrypt /
 * wc_AesGcmDecrypt) distinct from OpenSSL's EVP update loop and BoringSSL's
 * EVP_AEAD, so per PLAN 2.1 it carries its own L3 target. Links ONLY wolfCrypt.
 *
 *  mode 0  Nonce uniqueness (AES-256-GCM)
 *          GCM is a CTR-mode stream cipher: encrypting two messages under the
 *          same (key, nonce) leaks their XOR (ct1^ct2 == m1^m2 over the message
 *          bytes) and destroys authentication.
 *          O6-nonce-uniqueness : detect ct1^ct2 == m1^m2 under an identical nonce.
 *
 *  mode 1  Release-before-verify (wc_AesGcmDecrypt)
 *          wc_AesGcmDecrypt returns non-zero (AES_GCM_AUTH_E) and yields NO
 *          trustworthy plaintext on a forged/tampered input; the contract is to
 *          use the output only when it returns 0.
 *          O6-release-before-verify : delivering plaintext for a tampered
 *          ciphertext (decrypt failed) is a violation.
 *
 * Faults:
 *   CMF_FAULT_NONCE=1   : nonce source returns a constant -> O6-nonce-uniqueness.
 *   CMF_FAULT_RELEASE=1 : output used regardless of decrypt's result ->
 *                         O6-release-before-verify fires.
 */
#include <stdint.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include "../../engine/cmfuzz_common.h"

#define ALG "AES-256-GCM/wolfcrypt-seq"
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
                size_t mn, uint8_t *ct, uint8_t tag[TAGLEN]) {
    Aes aes;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return -1;
    int ok = wc_AesGcmSetKey(&aes, k, 32) == 0 &&
             wc_AesGcmEncrypt(&aes, ct, m, (word32)mn, n, NONCELEN,
                              tag, TAGLEN, NULL, 0) == 0;
    wc_AesFree(&aes);
    return ok ? 0 : -1;
}

static void test_nonce(cmf_reader_t *r) {
    uint8_t k[32]; cmf_randombytes(k, 32);
    const uint8_t *m; size_t mn = cmf_rest(r, &m);
    if (mn < 2) return; if (mn > 256) mn = 256;
    uint8_t m1[256], m2[256];
    memcpy(m1, m, mn); memcpy(m2, m, mn); m2[0] ^= 0xFF;
    uint8_t n1[NONCELEN], n2[NONCELEN], c1[256], c2[256], t1[TAGLEN], t2[TAGLEN];
    nonce_source(n1); int r1 = seal(k, n1, m1, mn, c1, t1);
    nonce_source(n2); int r2 = seal(k, n2, m2, mn, c2, t2);
    if (r1 < 0 || r2 < 0) return;
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
    int tamper = cmf_u8(r) & 1;
    const uint8_t *m; size_t mn = cmf_rest(r, &m);
    if (mn == 0) return; if (mn > 256) mn = 256;
    uint8_t ct[256], pt[256], tag[TAGLEN];
    if (seal(k, n, m, mn, ct, tag) < 0) return;
    if (tamper) ct[0] ^= 0x01;                 /* forge the ciphertext */
    Aes aes;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return;
    int decOk = wc_AesGcmSetKey(&aes, k, 32) == 0 &&
                wc_AesGcmDecrypt(&aes, pt, ct, (word32)mn, n, NONCELEN,
                                 tag, TAGLEN, NULL, 0) == 0;
    wc_AesFree(&aes);
#ifdef CMF_FAULT_RELEASE
    int deliver = 1;                           /* bug: use output regardless */
#else
    int deliver = decOk;                       /* contract: only on success */
#endif
    CMF_ASSERT(!(deliver && tamper), ALG, "O6-release-before-verify",
               "AES-GCM plaintext used without a successful decrypt (forgery accepted)");
    if (deliver && !tamper)
        CMF_ASSERT(memcmp(pt, m, mn) == 0, ALG, "O6-release-before-verify",
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
