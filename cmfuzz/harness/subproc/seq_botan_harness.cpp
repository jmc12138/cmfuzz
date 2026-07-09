/*
 * CMFuzz L3 (sequence / API-misuse) harness — Botan AEAD_Mode state machine.
 *
 * Botan (C++) models AEAD as an AEAD_Mode object: set_key -> set_associated_data
 * -> start(nonce) -> finish(buffer). Decryption's finish() THROWS
 * (Invalid_Authentication_Tag) on a forged/tampered input rather than returning
 * a status code — a different state machine from OpenSSL's EVP and BoringSSL's
 * EVP_AEAD, so per PLAN 2.1 it carries its own L3 target. Links ONLY Botan.
 *
 *  mode 0  Nonce uniqueness (AES-256/GCM)
 *          O6-nonce-uniqueness : reusing (key, nonce) leaks ct1^ct2 == m1^m2.
 *
 *  mode 1  Release-before-verify (decrypt finish() throws on forgery)
 *          O6-release-before-verify : using plaintext when finish() threw (i.e.
 *          the tag failed) is a violation.
 *
 * Faults:
 *   CMF_FAULT_NONCE=1   : nonce source returns a constant -> O6-nonce-uniqueness.
 *   CMF_FAULT_RELEASE=1 : output used even though decrypt threw ->
 *                         O6-release-before-verify fires.
 */
#include "botan_all.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include "../../engine/cmfuzz_common.h"

#define ALG "AES-256-GCM/botan-seq"
#define NONCELEN 12
#define TAGLEN   16

static void nonce_source(uint8_t n[NONCELEN]) {
#ifdef CMF_FAULT_NONCE
    memset(n, 0, NONCELEN);                    /* fault: reused/predictable nonce */
#else
    cmf_randombytes(n, NONCELEN);
#endif
}

/* Encrypt; buf receives ciphertext||tag. Returns false on any Botan error. */
static bool seal(const uint8_t k[32], const uint8_t n[NONCELEN], const uint8_t *m,
                 size_t mn, Botan::secure_vector<uint8_t> &buf) {
    try {
        auto enc = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        if (!enc) return false;
        enc->set_key(k, 32);
        enc->start(n, NONCELEN);
        buf.assign(m, m + mn);
        enc->finish(buf);
        return true;
    } catch (...) { return false; }
}

static void test_nonce(cmf_reader_t *r) {
    uint8_t k[32]; cmf_randombytes(k, 32);
    const uint8_t *m; size_t mn = cmf_rest(r, &m);
    if (mn < 2) return; if (mn > 256) mn = 256;
    std::vector<uint8_t> m1(m, m + mn), m2(m, m + mn); m2[0] ^= 0xFF;
    uint8_t n1[NONCELEN], n2[NONCELEN];
    Botan::secure_vector<uint8_t> c1, c2;
    nonce_source(n1); if (!seal(k, n1, m1.data(), mn, c1)) return;
    nonce_source(n2); if (!seal(k, n2, m2.data(), mn, c2)) return;
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
    Botan::secure_vector<uint8_t> ctbuf;
    if (!seal(k, n, m, mn, ctbuf)) return;
    if (tamper) ctbuf[0] ^= 0x01;              /* forge the ciphertext */
    bool decOk = false;
    Botan::secure_vector<uint8_t> pt = ctbuf;
    try {
        auto dec = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        if (dec) {
            dec->set_key(k, 32);
            dec->start(n, NONCELEN);
            dec->finish(pt);                   /* throws on tag failure */
            decOk = true;                      /* pt now = recovered plaintext */
        }
    } catch (...) { decOk = false; }
#ifdef CMF_FAULT_RELEASE
    int deliver = 1;                           /* bug: use output even if it threw */
#else
    int deliver = decOk ? 1 : 0;               /* contract: only after a clean finish() */
#endif
    CMF_ASSERT(!(deliver && tamper), ALG, "O6-release-before-verify",
               "AEAD plaintext used without a successful finish() (forgery accepted)");
    if (deliver && !tamper)
        CMF_ASSERT(pt.size() == mn && memcmp(pt.data(), m, mn) == 0, ALG,
                   "O6-release-before-verify", "verified plaintext != message");
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
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
