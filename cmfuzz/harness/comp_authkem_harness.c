/*
 * CMFuzz L2 (composition) harness — authenticated KEM (KEM + signature).
 *
 * Models "sign the encapsulation" authenticated key exchange: the sender KEM-
 * encapsulates to the recipient and SIGNS the encapsulation `enc`; the recipient
 * verifies the signature over `enc` BEFORE decapsulating, then both sides derive
 * an AEAD key via HKDF and exchange a record.
 *
 * Backends (-DCMF_AK_PQC):
 *   0 = classical  X25519 KEM + Ed25519 signature   (pure OpenSSL)
 *   1 = post-quantum ML-KEM-768 + ML-DSA-65          (liboqs)
 *
 * Composition oracles (O5):
 *   O5-roundtrip        : verify(sig) && decaps -> both sides derive same key ->
 *                         recipient opens the record == plaintext.
 *   O5-transcript-binding: flip a bit of `enc` (keep the signature) -> signature
 *                         verification MUST fail. This is the whole point of an
 *                         authenticated KEM: the signature must BIND the KEM
 *                         ciphertext, so an attacker cannot swap in a different
 *                         encapsulation. A composition that signs something that
 *                         does not cover `enc` would accept the swap.
 *
 * Fault CMF_FAULT_AK=1 : the authenticated transcript is a FIXED constant instead of
 *                        `enc` (both sign and verify), modeling a composition whose
 *                        signature does not actually bind the KEM ciphertext. The
 *                        roundtrip still verifies, but a tampered `enc` also verifies
 *                        -> O5-transcript-binding fires.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include "../engine/cmfuzz_common.h"

#ifndef CMF_AK_PQC
#define CMF_AK_PQC 0
#endif

/* What the signature binds to. Normally the KEM ciphertext `enc`; under the fault
 * a fixed constant (auth does not cover the transcript). */
static const uint8_t AK_FIXED[4] = {0, 0, 0, 0};
#ifdef CMF_FAULT_AK
#define AK_MSG(encptr, enclen, mp, ml) do { (mp) = AK_FIXED; (ml) = sizeof AK_FIXED; } while (0)
#else
#define AK_MSG(encptr, enclen, mp, ml) do { (mp) = (encptr); (ml) = (enclen); } while (0)
#endif

#if CMF_AK_PQC == 1
#include <oqs/oqs.h>
#define AK_NAME "AuthKEM(ML-KEM-768+ML-DSA-65)"
#else
#define AK_NAME "AuthKEM(X25519+Ed25519)"
#endif

static int hkdf32(const uint8_t *ss, size_t sslen, uint8_t out[32]) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[4], *p = params;
    char digest[] = "SHA256";
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ss, sslen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)"ak", 2);
    *p = OSSL_PARAM_construct_end();
    int ok = EVP_KDF_derive(kctx, out, 32, params) > 0;
    EVP_KDF_CTX_free(kctx); EVP_KDF_free(kdf);
    return ok;
}
static int gcm_seal(const uint8_t k[32], const uint8_t *m, int n, uint8_t *out) {
    uint8_t nonce[12] = {0};
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, ctn = 0;
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, k, nonce);
    EVP_EncryptUpdate(c, out, &l, m, n); ctn = l;
    EVP_EncryptFinal_ex(c, out + ctn, &l); ctn += l;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, out + ctn);
    EVP_CIPHER_CTX_free(c); return ctn + 16;
}
static int gcm_open(const uint8_t k[32], const uint8_t *ct, int ctn, uint8_t *out) {
    uint8_t nonce[12] = {0};
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, ok;
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, k, nonce);
    EVP_DecryptUpdate(c, out, &l, ct, ctn - 16);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(ct + ctn - 16));
    ok = EVP_DecryptFinal_ex(c, out + l, &l);
    EVP_CIPHER_CTX_free(c); return ok == 1;
}

#if CMF_AK_PQC == 1
static OQS_KEM *g_kem; static OQS_SIG *g_sig;
#define ENC_LEN (g_kem->length_ciphertext)
#define SS_LEN  (g_kem->length_shared_secret)
static void run_case(cmf_reader_t *r) {
    g_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    g_sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!g_kem || !g_sig) goto done;
    uint8_t *pkR = malloc(g_kem->length_public_key), *skR = malloc(g_kem->length_secret_key);
    uint8_t *pkS = malloc(g_sig->length_public_key), *skS = malloc(g_sig->length_secret_key);
    uint8_t *enc = malloc(g_kem->length_ciphertext), ss_s[64], ss_r[64];
    uint8_t *sig = malloc(g_sig->length_signature); size_t siglen = 0;
    if (OQS_KEM_keypair(g_kem, pkR, skR) != OQS_SUCCESS) goto freeall;
    if (OQS_SIG_keypair(g_sig, pkS, skS) != OQS_SUCCESS) goto freeall;
    if (OQS_KEM_encaps(g_kem, enc, ss_s, pkR) != OQS_SUCCESS) goto freeall;
    const uint8_t *sm; size_t sml;
    AK_MSG(enc, g_kem->length_ciphertext, sm, sml);
    OQS_SIG_sign(g_sig, sig, &siglen, sm, sml, skS);
    /* O5-roundtrip */
    int v = OQS_SIG_verify(g_sig, sm, sml, sig, siglen, pkS) == OQS_SUCCESS;
    CMF_ASSERT(v, AK_NAME, "O5-roundtrip", "signature over enc failed to verify");
    if (OQS_KEM_decaps(g_kem, ss_r, enc, skR) == OQS_SUCCESS) {
        uint8_t ks[32], kr[32], ctb[1024 + 16], pt[1024];
        const uint8_t *m; size_t mn = cmf_rest(r, &m); if (mn > 1024) mn = 1024;
        hkdf32(ss_s, g_kem->length_shared_secret, ks);
        hkdf32(ss_r, g_kem->length_shared_secret, kr);
        int cn = gcm_seal(ks, m, (int)mn, ctb);
        int ok = gcm_open(kr, ctb, cn, pt);
        CMF_ASSERT(ok && memcmp(pt, m, mn) == 0, AK_NAME, "O5-roundtrip", "AEAD record mismatch");
    }
    /* O5-transcript-binding: tamper enc, keep sig -> verify must fail */
    {
        uint8_t save = enc[0]; enc[0] ^= 0x01;
        const uint8_t *tm; size_t tml; AK_MSG(enc, g_kem->length_ciphertext, tm, tml);
        int v2 = OQS_SIG_verify(g_sig, tm, tml, sig, siglen, pkS) == OQS_SUCCESS;
        CMF_ASSERT(!v2, AK_NAME, "O5-transcript-binding", "signature accepted a swapped encapsulation");
        enc[0] = save;
    }
freeall:
    free(pkR); free(skR); free(pkS); free(skS); free(enc); free(sig);
done:
    if (g_kem) OQS_KEM_free(g_kem);
    if (g_sig) OQS_SIG_free(g_sig);
    g_kem = NULL; g_sig = NULL;
}
#else
/* classical X25519 + Ed25519 (OpenSSL) */
static int x25519_pub(EVP_PKEY *k, uint8_t o[32]) { size_t l = 32; return EVP_PKEY_get_raw_public_key(k, o, &l) == 1; }
static int x25519_ecdh(EVP_PKEY *priv, const uint8_t pub[32], uint8_t ss[32]) {
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, 32);
    if (!peer) return 0;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL); size_t l = 32; int ok = 0;
    if (ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
        EVP_PKEY_derive(ctx, ss, &l) == 1) ok = 1;
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer); return ok;
}
static int ed_sign(EVP_PKEY *sk, const uint8_t *m, size_t n, uint8_t sig[64]) {
    EVP_MD_CTX *c = EVP_MD_CTX_new(); size_t sl = 64; int ok = 0;
    if (EVP_DigestSignInit(c, NULL, NULL, NULL, sk) == 1 &&
        EVP_DigestSign(c, sig, &sl, m, n) == 1) ok = 1;
    EVP_MD_CTX_free(c); return ok;
}
static int ed_verify(EVP_PKEY *pk, const uint8_t *m, size_t n, const uint8_t sig[64]) {
    EVP_MD_CTX *c = EVP_MD_CTX_new(); int ok = 0;
    if (EVP_DigestVerifyInit(c, NULL, NULL, NULL, pk) == 1 &&
        EVP_DigestVerify(c, sig, 64, m, n) == 1) ok = 1;
    EVP_MD_CTX_free(c); return ok;
}
static void run_case(cmf_reader_t *r) {
    EVP_PKEY *skR = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    EVP_PKEY *eph = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    EVP_PKEY *skS = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (!skR || !eph || !skS) goto done;
    uint8_t pkR[32], enc[32], ss_s[32], ss_r[32], sig[64];
    x25519_pub(skR, pkR);
    x25519_pub(eph, enc);              /* enc = ephemeral public key */
    if (!x25519_ecdh(eph, pkR, ss_s)) goto done;
    const uint8_t *sm; size_t sml; AK_MSG(enc, 32, sm, sml);
    ed_sign(skS, sm, sml, sig);        /* sign the (authenticated) transcript */
    /* O5-roundtrip */
    CMF_ASSERT(ed_verify(skS, sm, sml, sig), AK_NAME, "O5-roundtrip",
               "signature over enc failed to verify");
    if (x25519_ecdh(skR, enc, ss_r)) {
        uint8_t ks[32], kr[32], ctb[1024 + 16], pt[1024];
        const uint8_t *m; size_t mn = cmf_rest(r, &m); if (mn > 1024) mn = 1024;
        hkdf32(ss_s, 32, ks); hkdf32(ss_r, 32, kr);
        int cn = gcm_seal(ks, m, (int)mn, ctb);
        int ok = gcm_open(kr, ctb, cn, pt);
        CMF_ASSERT(ok && memcmp(pt, m, mn) == 0, AK_NAME, "O5-roundtrip", "AEAD record mismatch");
    }
    /* O5-transcript-binding: tamper enc, keep sig -> verify must fail */
    {
        uint8_t bad[32]; memcpy(bad, enc, 32); bad[0] ^= 0x01;
        const uint8_t *tm; size_t tml; AK_MSG(bad, 32, tm, tml);
        CMF_ASSERT(!ed_verify(skS, tm, tml, sig), AK_NAME, "O5-transcript-binding",
                   "signature accepted a swapped encapsulation");
    }
done:
    EVP_PKEY_free(skR); EVP_PKEY_free(eph); EVP_PKEY_free(skS);
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    cmf_prng_seed(data, size);
    cmf_reader_t r; cmf_reader_init(&r, data, size);
    run_case(&r);
    return 0;
}
