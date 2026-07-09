/*
 * CMFuzz multi-library differential harness (Cryptofuzz-style cross-checking).
 *
 * Runs the SAME primitive across OpenSSL, libsodium, Mbed-TLS and Crypto++ on
 * one fuzzer-derived input and asserts every implementation agrees. Any
 * disagreement is a differential bug (one library is wrong, or specs differ).
 *
 * Primitives: SHA-256, SHA-512, HMAC-SHA256, ChaCha20-Poly1305 (IETF),
 *             AES-256-GCM.
 *
 * Build: see scripts/build_harness.sh (target DIFF).
 */
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>

#include "../engine/cmfuzz_common.h"

/* ---- OpenSSL ---- */
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* ---- libsodium ---- */
#include <sodium.h>

/* ---- Mbed-TLS ---- */
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <mbedtls/chachapoly.h>

/* ---- Crypto++ ---- */
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/chachapoly.h>
#include <cryptopp/filters.h>

using bytes = std::vector<uint8_t>;

static void hexcmp_fail(const char *prim, const char *a, const char *b) {
    /* both are library names that disagreed */
    char msg[128];
    snprintf(msg, sizeof msg, "%s vs %s disagree", a, b);
    CMF_VIOLATION(prim, "DIFF_mismatch", msg);
}

/* Compare a set of (name,digest) results; abort on first mismatch. */
static void agree(const char *prim,
                  const std::vector<std::pair<const char*, bytes>> &rs) {
    for (size_t i = 1; i < rs.size(); i++) {
        if (rs[i].second != rs[0].second)
            hexcmp_fail(prim, rs[0].first, rs[i].first);
    }
}

/* ============================ digests ============================ */
static void test_sha256(const uint8_t *m, size_t n) {
    std::vector<std::pair<const char*, bytes>> rs;

    bytes o(32);
    unsigned int ol = 32;
    EVP_Digest(m, n, o.data(), &ol, EVP_sha256(), nullptr);
    rs.push_back({"openssl", o});

    bytes s(32);
    crypto_hash_sha256(s.data(), m, n);
    rs.push_back({"libsodium", s});

    bytes mb(32);
    mbedtls_sha256(m, n, mb.data(), 0);
    rs.push_back({"mbedtls", mb});

    bytes cp(32);
    CryptoPP::SHA256().CalculateDigest(cp.data(), m, n);
#ifdef CMF_DIFF_FAULT
    /* self-test hook: corrupt one implementation so the differential oracle
     * must fire (proves cross-checking actually detects a divergence). */
    cp[0] ^= 0xFF;
#endif
    rs.push_back({"cryptopp", cp});

    agree("SHA-256", rs);
}

static void test_sha512(const uint8_t *m, size_t n) {
    std::vector<std::pair<const char*, bytes>> rs;

    bytes o(64);
    unsigned int ol = 64;
    EVP_Digest(m, n, o.data(), &ol, EVP_sha512(), nullptr);
    rs.push_back({"openssl", o});

    bytes s(64);
    crypto_hash_sha512(s.data(), m, n);
    rs.push_back({"libsodium", s});

    bytes mb(64);
    mbedtls_sha512(m, n, mb.data(), 0);
    rs.push_back({"mbedtls", mb});

    bytes cp(64);
    CryptoPP::SHA512().CalculateDigest(cp.data(), m, n);
    rs.push_back({"cryptopp", cp});

    agree("SHA-512", rs);
}

/* ============================ HMAC-SHA256 ======================== */
static void test_hmac256(const uint8_t key[32], const uint8_t *m, size_t n) {
    std::vector<std::pair<const char*, bytes>> rs;

    bytes o(32);
    unsigned int ol = 32;
    HMAC(EVP_sha256(), key, 32, m, n, o.data(), &ol);
    rs.push_back({"openssl", o});

    bytes s(32);
    crypto_auth_hmacsha256(s.data(), m, n, key);   /* key fixed 32B */
    rs.push_back({"libsodium", s});

    bytes mb(32);
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    key, 32, m, n, mb.data());
    rs.push_back({"mbedtls", mb});

    bytes cp(32);
    {
        CryptoPP::HMAC<CryptoPP::SHA256> h(key, 32);
        h.CalculateDigest(cp.data(), m, n);
    }
    rs.push_back({"cryptopp", cp});

    agree("HMAC-SHA256", rs);
}

/* ==================== ChaCha20-Poly1305 (IETF) =================== */
static void test_chachapoly(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *m, size_t n,
                            const uint8_t *aad, size_t adn) {
    std::vector<std::pair<const char*, bytes>> rs;

    /* OpenSSL */
    {
        bytes ct(n + 16);
        int len = 0, ctl = 0;
        EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, key, nonce);
        if (adn) EVP_EncryptUpdate(c, nullptr, &len, aad, (int)adn);
        EVP_EncryptUpdate(c, ct.data(), &len, m, (int)n); ctl = len;
        EVP_EncryptFinal_ex(c, ct.data() + ctl, &len); ctl += len;
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, ct.data() + ctl);
        ct.resize(n + 16);
        EVP_CIPHER_CTX_free(c);
        rs.push_back({"openssl", ct});
    }
    /* libsodium: ct||tag layout matches OpenSSL (ct then 16B tag) */
    {
        bytes ct(n + 16);
        unsigned long long clen = 0;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ct.data(), &clen, m, n, aad, adn, nullptr, nonce, key);
        ct.resize(clen);
        rs.push_back({"libsodium", ct});
    }
    /* Mbed-TLS */
    {
        bytes ct(n), tag(16);
        mbedtls_chachapoly_context cc;
        mbedtls_chachapoly_init(&cc);
        mbedtls_chachapoly_setkey(&cc, key);
        mbedtls_chachapoly_encrypt_and_tag(&cc, n, nonce, aad, adn,
                                           m, ct.data(), tag.data());
        mbedtls_chachapoly_free(&cc);
        ct.insert(ct.end(), tag.begin(), tag.end());
        rs.push_back({"mbedtls", ct});
    }
    /* Crypto++ */
    {
        bytes ct(n + 16);
        CryptoPP::ChaCha20Poly1305::Encryption enc;
        enc.SetKeyWithIV(key, 32, nonce, 12);
        enc.EncryptAndAuthenticate(ct.data(), ct.data() + n, 16,
                                   nonce, 12, aad, adn, m, n);
        rs.push_back({"cryptopp", ct});
    }
    agree("ChaCha20-Poly1305", rs);
}

/* ========================= AES-256-GCM =========================== */
static void test_aesgcm(const uint8_t key[32], const uint8_t iv[12],
                        const uint8_t *m, size_t n,
                        const uint8_t *aad, size_t adn) {
    std::vector<std::pair<const char*, bytes>> rs;

    /* OpenSSL */
    {
        bytes ct(n + 16);
        int len = 0, ctl = 0;
        EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(c, nullptr, nullptr, key, iv);
        if (adn) EVP_EncryptUpdate(c, nullptr, &len, aad, (int)adn);
        EVP_EncryptUpdate(c, ct.data(), &len, m, (int)n); ctl = len;
        EVP_EncryptFinal_ex(c, ct.data() + ctl, &len); ctl += len;
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, ct.data() + ctl);
        EVP_CIPHER_CTX_free(c);
        rs.push_back({"openssl", ct});
    }
    /* Mbed-TLS */
    {
        bytes ct(n), tag(16);
        mbedtls_gcm_context g;
        mbedtls_gcm_init(&g);
        mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
        mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, n, iv, 12,
                                  aad, adn, m, ct.data(), 16, tag.data());
        mbedtls_gcm_free(&g);
        ct.insert(ct.end(), tag.begin(), tag.end());
        rs.push_back({"mbedtls", ct});
    }
    /* Crypto++ */
    {
        bytes ct(n + 16);
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, 32, iv, 12);
        enc.EncryptAndAuthenticate(ct.data(), ct.data() + n, 16,
                                   iv, 12, aad, adn, m, n);
        rs.push_back({"cryptopp", ct});
    }
    /* libsodium (only if hardware AES-GCM available) */
    if (crypto_aead_aes256gcm_is_available()) {
        bytes ct(n + 16);
        unsigned long long clen = 0;
        crypto_aead_aes256gcm_encrypt(ct.data(), &clen, m, n, aad, adn,
                                      nullptr, iv, key);
        ct.resize(clen);
        rs.push_back({"libsodium", ct});
    }
    agree("AES-256-GCM", rs);
}

/* ============================ driver ============================= */
extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    if (sodium_init() < 0) abort();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    cmf_prng_seed(data, size);

    cmf_reader_t r; cmf_reader_init(&r, data, size);
    uint8_t op = cmf_u8(&r) % 5;
    uint8_t split = cmf_u8(&r);

    /* derive fixed key/nonce material deterministically */
    uint8_t key[32], nonce[12];
    cmf_randombytes(key, 32);
    cmf_randombytes(nonce, 12);

    /* split the rest into aad + message */
    const uint8_t *p = nullptr;
    size_t rem = cmf_rest(&r, &p);
    size_t adn = rem ? (split % (rem + 1)) : 0;
    if (adn > rem) adn = rem;
    const uint8_t *aad = p;
    const uint8_t *msg = p + adn;
    size_t mlen = rem - adn;

    switch (op) {
        case 0: test_sha256(p, rem); break;
        case 1: test_sha512(p, rem); break;
        case 2: test_hmac256(key, p, rem); break;
        case 3: test_chachapoly(key, nonce, msg, mlen, aad, adn); break;
        case 4: test_aesgcm(key, nonce, msg, mlen, aad, adn); break;
    }
    return 0;
}
