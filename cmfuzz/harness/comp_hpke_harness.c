/*
 * CMFuzz L2 (composition) harness — HPKE-style KEM + KDF + AEAD.
 *
 * Lifts testing from single-primitive correctness (L1) to the COMPOSITION layer
 * (L2): several primitives chained the standard HPKE way. We build the seal/open
 * flow ourselves from primitives (OpenSSL 3.0.2 has no OSSL_HPKE_* API), which is
 * exactly the composition we want under test.
 *
 * Two KEM backends (compile-time -DCMF_HPKE_KEM):
 *   0 = classical  X25519           (pure OpenSSL)
 *   1 = post-quantum ML-KEM-768     (liboqs)
 * Shared KDF = HKDF-SHA256, AEAD = AES-256-GCM.
 *
 * Composition oracles (O5):
 *   O5-roundtrip        : recipient.open(sender.seal(m)) == m
 *   O5-context-binding  : changing info/aad at open time -> open MUST fail
 *   O5-upstream-tamper  : tampering the encapsulated key `enc` -> recipient derives
 *                         a different shared secret -> open MUST fail (auth reject).
 *                         This is the key point: a malleability/decaps quirk that a
 *                         single-primitive (L1) test might rate a benign "feature"
 *                         becomes an end-to-end failure at the composition layer.
 *
 * Build CMF_FAULT_HPKE=1 for the fault-injected self-test: the recipient ignores a
 * tampered `enc` (uses the sender's shared secret), so O5-upstream-tamper must fire.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include "../engine/cmfuzz_common.h"

#ifndef CMF_HPKE_KEM
#define CMF_HPKE_KEM 0
#endif

#if CMF_HPKE_KEM == 1
#include <oqs/oqs.h>
#define KEM_NAME "HPKE(ML-KEM-768+HKDF+AES-GCM)"
#else
#define KEM_NAME "HPKE(X25519+HKDF+AES-GCM)"
#endif

/* HKDF-SHA256 extract+expand into out[outlen], info-bound. */
static int hkdf(const uint8_t *ss, size_t sslen,
                const uint8_t *info, size_t infolen,
                uint8_t *out, size_t outlen) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[5], *p = params;
    char digest[] = "SHA256";
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ss, sslen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, infolen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)"", 0);
    *p = OSSL_PARAM_construct_end();
    int ok = EVP_KDF_derive(kctx, out, outlen, params) > 0;
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ok;
}

/* AES-256-GCM seal -> out = ct||tag (len n+16); returns len. */
static int gcm_seal(const uint8_t key[32], const uint8_t nonce[12],
                    const uint8_t *aad, int adn,
                    const uint8_t *m, int n, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len = 0, ctl = 0;
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(c, NULL, NULL, key, nonce);
    if (adn) EVP_EncryptUpdate(c, NULL, &len, aad, adn);
    EVP_EncryptUpdate(c, out, &len, m, n); ctl = len;
    EVP_EncryptFinal_ex(c, out + ctl, &len); ctl += len;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, out + ctl);
    EVP_CIPHER_CTX_free(c);
    return ctl + 16;
}

/* AES-256-GCM open; returns 1 if tag verifies. */
static int gcm_open(const uint8_t key[32], const uint8_t nonce[12],
                    const uint8_t *aad, int adn,
                    const uint8_t *ct, int ctn, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len = 0, ok;
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(c, NULL, NULL, key, nonce);
    if (adn) EVP_DecryptUpdate(c, NULL, &len, aad, adn);
    EVP_DecryptUpdate(c, out, &len, ct, ctn - 16);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(ct + ctn - 16));
    ok = EVP_DecryptFinal_ex(c, out + len, &len);
    EVP_CIPHER_CTX_free(c);
    return ok == 1;
}

/* Derive AEAD key+nonce from shared secret, HPKE-style (info-bound). */
static int key_schedule(const uint8_t *ss, size_t sslen,
                        const uint8_t *info, size_t infolen,
                        uint8_t key[32], uint8_t nonce[12]) {
    uint8_t okm[44];
    if (!hkdf(ss, sslen, info, infolen, okm, sizeof okm)) return 0;
    memcpy(key, okm, 32);
    memcpy(nonce, okm + 32, 12);
    return 1;
}

/* ---- KEM backend: encaps -> (enc, ss_send); decaps(enc) -> ss_recv --------- */
#if CMF_HPKE_KEM == 1
/* ML-KEM-768 via liboqs. */
static OQS_KEM *g_kem;
static int kem_setup(uint8_t **pk, uint8_t **sk) {
    g_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!g_kem) return 0;
    *pk = malloc(g_kem->length_public_key);
    *sk = malloc(g_kem->length_secret_key);
    return OQS_KEM_keypair(g_kem, *pk, *sk) == OQS_SUCCESS;
}
static int kem_encaps(const uint8_t *pk, uint8_t *enc, uint8_t *ss) {
    return OQS_KEM_encaps(g_kem, enc, ss, pk) == OQS_SUCCESS;
}
static int kem_decaps(const uint8_t *sk, const uint8_t *enc, uint8_t *ss) {
    return OQS_KEM_decaps(g_kem, ss, enc, sk) == OQS_SUCCESS;
}
#define ENC_LEN   (g_kem->length_ciphertext)
#define SS_LEN    (g_kem->length_shared_secret)
#define PK_LEN    (g_kem->length_public_key)
static void kem_teardown(uint8_t *pk, uint8_t *sk) {
    free(pk); free(sk); OQS_KEM_free(g_kem); g_kem = NULL;
}
#else
/* X25519 via OpenSSL. enc = ephemeral public key (32B); ss = ECDH(eph, pkR). */
#define ENC_LEN 32
#define SS_LEN  32
#define PK_LEN  32
static EVP_PKEY *g_skR;      /* recipient private key */
static uint8_t g_pkR[32];    /* recipient public key */

static int x25519_pub(EVP_PKEY *k, uint8_t out[32]) {
    size_t l = 32; return EVP_PKEY_get_raw_public_key(k, out, &l) == 1;
}
static int kem_setup(uint8_t **pk, uint8_t **sk) {
    g_skR = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (!g_skR) return 0;
    if (!x25519_pub(g_skR, g_pkR)) return 0;
    *pk = g_pkR; *sk = NULL;
    return 1;
}
/* ECDH shared secret between private `priv` and raw public `pub32`. */
static int x25519_ecdh(EVP_PKEY *priv, const uint8_t pub32[32], uint8_t ss[32]) {
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub32, 32);
    if (!peer) return 0;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    size_t l = 32; int ok = 0;
    if (ctx && EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
        EVP_PKEY_derive(ctx, ss, &l) == 1) ok = 1;
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer);
    return ok;
}
static EVP_PKEY *g_eph;   /* sender ephemeral, kept so decaps side is symmetric */
static int kem_encaps(const uint8_t *pkR, uint8_t *enc, uint8_t *ss) {
    g_eph = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (!g_eph) return 0;
    if (!x25519_pub(g_eph, enc)) return 0;         /* enc = ephemeral public */
    return x25519_ecdh(g_eph, pkR, ss);            /* ss = ECDH(eph, pkR) */
}
static int kem_decaps(const uint8_t *skR_unused, const uint8_t *enc, uint8_t *ss) {
    (void)skR_unused;
    return x25519_ecdh(g_skR, enc, ss);            /* ss = ECDH(skR, enc) */
}
static void kem_teardown(uint8_t *pk, uint8_t *sk) {
    (void)pk; (void)sk;
    EVP_PKEY_free(g_skR); EVP_PKEY_free(g_eph); g_skR = g_eph = NULL;
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 6) return 0;
    cmf_prng_seed(data, size);
    cmf_reader_t r; cmf_reader_init(&r, data, size);
    uint8_t split = cmf_u8(&r);
    uint8_t tflag = cmf_u8(&r);           /* which tamper to exercise */
    const uint8_t *p; size_t rem = cmf_rest(&r, &p);
    if (rem > 2048) rem = 2048;
    size_t infolen = rem ? (split % (rem + 1)) : 0;
    const uint8_t *info = p, *msg = p + infolen;
    size_t mlen = rem - infolen;
    const uint8_t *aad = info;            /* reuse info bytes as aad for binding test */
    int adn = (int)infolen;

    uint8_t *pk = NULL, *sk = NULL;
    if (!kem_setup(&pk, &sk)) return 0;

    uint8_t enc[64] = {0}, ss_send[64] = {0}, ss_recv[64] = {0};
    if (ENC_LEN > sizeof enc || SS_LEN > sizeof ss_send) { kem_teardown(pk, sk); return 0; }
    if (!kem_encaps(pk, enc, ss_send)) { kem_teardown(pk, sk); return 0; }

    /* sender key schedule + seal */
    uint8_t ks[32], ns[12];
    if (!key_schedule(ss_send, SS_LEN, info, infolen, ks, ns)) { kem_teardown(pk, sk); return 0; }
    uint8_t ct[2048 + 16];
    int ctn = gcm_seal(ks, ns, aad, adn, msg, (int)mlen, ct);

    /* ---- O5-roundtrip: recipient decaps -> key schedule -> open ---- */
    if (!kem_decaps(sk, enc, ss_recv)) { kem_teardown(pk, sk); return 0; }
    uint8_t kr[32], nr[12], pt[2048];
    key_schedule(ss_recv, SS_LEN, info, infolen, kr, nr);
    int ok = gcm_open(kr, nr, aad, adn, ct, ctn, pt);
    CMF_ASSERT(ok, KEM_NAME, "O5-roundtrip", "recipient failed to open sealed message");
    CMF_ASSERT(memcmp(pt, msg, mlen) == 0, KEM_NAME, "O5-roundtrip", "opened plaintext != message");

    /* ---- O5-context-binding: change info at open time -> must fail ---- */
    if (tflag & 1) {
        uint8_t kr2[32], nr2[12];
        uint8_t altinfo[8] = {0xA5,0,0,0,0,0,0,0};
        key_schedule(ss_recv, SS_LEN, altinfo, sizeof altinfo, kr2, nr2);
        int ok2 = gcm_open(kr2, nr2, aad, adn, ct, ctn, pt);
        CMF_ASSERT(!ok2, KEM_NAME, "O5-context-binding", "different info still opened ciphertext");
    }

    /* ---- O5-upstream-tamper: corrupt encapsulated key -> open must fail ---- */
    {
        uint8_t enc_bad[64]; memcpy(enc_bad, enc, ENC_LEN);
        enc_bad[tflag % ENC_LEN] ^= 0x01;      /* flip one bit of enc */
        uint8_t ssb[64] = {0}, kb[32], nb[12];
        int dec_ok = kem_decaps(sk, enc_bad, ssb);
#ifdef CMF_FAULT_HPKE
        /* fault: ignore the tamper, pretend recipient got the sender's secret */
        memcpy(ssb, ss_send, SS_LEN); dec_ok = 1;
#endif
        if (dec_ok) {
            key_schedule(ssb, SS_LEN, info, infolen, kb, nb);
            int ok3 = gcm_open(kb, nb, aad, adn, ct, ctn, pt);
            CMF_ASSERT(!ok3, KEM_NAME, "O5-upstream-tamper",
                       "tampered encapsulated key still opened ciphertext");
        }
    }

    kem_teardown(pk, sk);
    return 0;
}
