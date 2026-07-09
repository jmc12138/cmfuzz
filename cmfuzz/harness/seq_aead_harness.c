/*
 * CMFuzz L3 (sequence / API-misuse) harness — stateful AEAD contracts (O6).
 *
 * Unlike L1/L2 (which test a single call or a fixed composition), L3 tests
 * *operation sequences* against the library's usage contract. Two contracts,
 * both on traditional AES-256-GCM, selected per-input:
 *
 *  mode 0  Nonce uniqueness (catastrophic-nonce-reuse detector)
 *          A correct protocol draws a FRESH nonce per message from a nonce
 *          source. We drive two encryptions from the source and check:
 *          O6-nonce-uniqueness : the source never repeats a (key,nonce) pair.
 *          When it does repeat, GCM degenerates to a two-time pad and
 *          ct1 XOR ct2 == m1 XOR m2 (keystream leak) — we surface that as the
 *          concrete security consequence.
 *
 *  mode 1  Release-before-verify (AEAD decrypt state machine)
 *          The AEAD contract is: NEVER use the plaintext produced by
 *          DecryptUpdate until DecryptFinal (tag verification) succeeds.
 *          We run Update (which yields candidate plaintext) then Final, and
 *          check:
 *          O6-release-before-verify : plaintext is delivered only if Final
 *          succeeded; delivering it for a tampered ciphertext is a violation.
 *
 * Faults:
 *   CMF_FAULT_NONCE=1   : nonce source returns a constant -> O6-nonce-uniqueness fires.
 *   CMF_FAULT_RELEASE=1 : plaintext used regardless of Final -> O6-release-before-verify fires.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include "../engine/cmfuzz_common.h"

#define ALG "AES-256-GCM/seq"

/* A per-key nonce source. Correct: monotonic counter (never repeats within key
 * lifetime). Fault: constant (always the same nonce). */
static void nonce_source(uint64_t *ctr, uint8_t nonce[12]) {
    memset(nonce, 0, 12);
#ifdef CMF_FAULT_NONCE
    (void)ctr;                              /* fault: constant nonce */
#else
    for (int i = 0; i < 8; i++) nonce[11 - i] = (uint8_t)((*ctr) >> (8 * i));
    (*ctr)++;
#endif
}

static int gcm_seal(const uint8_t k[32], const uint8_t n[12], const uint8_t *m, int mn,
                    uint8_t *ct, uint8_t tag[16]) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, cn = 0;
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(c, NULL, NULL, k, n);
    EVP_EncryptUpdate(c, ct, &l, m, mn); cn = l;
    EVP_EncryptFinal_ex(c, ct + cn, &l); cn += l;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(c);
    return cn;
}

static void test_nonce(cmf_reader_t *r) {
    uint8_t k[32]; cmf_randombytes(k, 32);
    uint64_t ctr = 0;
    uint8_t m1[64], m2[64];
    cmf_randombytes(m1, 64); cmf_randombytes(m2, 64);
    m1[0] = 0x11; m2[0] = 0x22;              /* keep the two messages distinct */
    uint8_t n1[12], n2[12], c1[64], c2[64], t1[16], t2[16];
    nonce_source(&ctr, n1); gcm_seal(k, n1, m1, 64, c1, t1);
    nonce_source(&ctr, n2); gcm_seal(k, n2, m2, 64, c2, t2);
    int reused = memcmp(n1, n2, 12) == 0;
    CMF_ASSERT(!reused, ALG, "O6-nonce-uniqueness",
               "nonce source repeated a (key,nonce) pair");
    if (reused) {
        /* Concrete consequence: two-time pad — keystream cancels out. */
        int leak = 1;
        for (int i = 0; i < 64; i++)
            if ((c1[i] ^ c2[i]) != (m1[i] ^ m2[i])) { leak = 0; break; }
        CMF_ASSERT(!leak, ALG, "O6-nonce-uniqueness",
                   "nonce reuse leaked plaintext XOR (two-time pad)");
    }
    (void)r;
}

static void test_release(cmf_reader_t *r) {
    uint8_t k[32], n[12]; cmf_randombytes(k, 32); cmf_randombytes(n, 12);
    int tamper = cmf_u8(r) & 1;              /* decide whether to forge (read BEFORE rest) */
    const uint8_t *m; size_t mn = cmf_rest(r, &m); if (mn > 512) mn = 512;
    if (mn == 0) return;
    uint8_t ct[512], tag[16], pcand[512];
    int cn = gcm_seal(k, n, m, (int)mn, ct, tag);

    if (tamper) ct[(size_t)(cmf_splitmix64(&g_cmf_prng.state) % (uint64_t)cn)] ^= 0x01;

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0;
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(c, NULL, NULL, k, n);
    EVP_DecryptUpdate(c, pcand, &l, ct, cn);  /* candidate plaintext (UNVERIFIED) */
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, tag);
    int finOk = EVP_DecryptFinal_ex(c, pcand + l, &l) == 1;
    EVP_CIPHER_CTX_free(c);

#ifdef CMF_FAULT_RELEASE
    int deliver = 1;                          /* bug: use plaintext regardless of Final */
#else
    int deliver = finOk;                      /* contract: only after successful verify */
#endif
    /* Delivering plaintext for a tampered ciphertext == release of unverified data. */
    CMF_ASSERT(!(deliver && tamper), ALG, "O6-release-before-verify",
               "AEAD plaintext used before/without successful tag verification");
    if (deliver && !tamper)                   /* authentic path must round-trip */
        CMF_ASSERT(memcmp(pcand, m, mn) == 0, ALG, "O6-release-before-verify",
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
    test_release(&r); return 0;
#endif
    if (mode & 1) test_release(&r);
    else          test_nonce(&r);
    return 0;
}
