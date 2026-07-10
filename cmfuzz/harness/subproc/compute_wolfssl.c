/*
 * CMFuzz subprocess differential CLI — wolfCrypt backend (stage 2.1).
 *
 * Standalone binary linking ONLY wolfSSL/wolfCrypt. wolfCrypt exposes its own
 * native API (wc_Sha256Hash, wc_HmacSetKey, wc_ChaCha20Poly1305_Encrypt,
 * wc_AesGcmEncrypt) with a distinct state machine from OpenSSL's EVP; keeping it
 * behind a subprocess gives a uniform, byte-exact differential. Reads request
 * lines on stdin, prints one hex output line per request (see compute_common.h).
 *
 * CMF_DIFF_FAULT=1 flips the first output byte, so the differential runner's
 * negative self-test can prove it actually catches a divergent implementation.
 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include "compute_common.h"

/* RSA-PSS verify-interop (op14): rebuild the public key from the raw modulus n
 * (exponent fixed at 65537), verify RSA-PSS(SHA-256, MGF1-SHA-256, salt=32) over
 * SHA-256(message); reply 1-byte accept/reject. */
static int rsa_pss_verify(const cmf_vec_t *v, uint8_t *out, size_t *n_out) {
    const uint8_t *pub, *sig, *msg; size_t publen, siglen, mlen;
    int verdict = 0;
    if (cmf_verify_parse(v->msg, v->msglen, &pub, &publen, &sig, &siglen, &msg, &mlen) == 0) {
        static const uint8_t e[3] = { 0x01, 0x00, 0x01 };   /* 65537 */
        uint8_t d[WC_SHA256_DIGEST_SIZE];
        RsaKey key;
        if (wc_Sha256Hash(msg, (word32)mlen, d) == 0 && wc_InitRsaKey(&key, NULL) == 0) {
            uint8_t rec[512];
            if (wc_RsaPublicKeyDecodeRaw(pub, (word32)publen, e, sizeof e, &key) == 0 &&
                wc_RsaPSS_VerifyCheck((byte *)sig, (word32)siglen, rec, sizeof rec,
                                      d, sizeof d, WC_HASH_TYPE_SHA256,
                                      WC_MGF1SHA256, &key) > 0)
                verdict = 1;
            wc_FreeRsaKey(&key);
        }
    }
    out[0] = (uint8_t)verdict; *n_out = 1; return 0;
}

/* ECDSA-P256 verify-interop (op13): import the SEC1 uncompressed public point
 * (wc_ecc_import_x963 infers SECP256R1 from the 65-byte length), verify the DER
 * signature over SHA-256(message); reply 1-byte accept/reject. */
static int ecdsa_verify(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    const uint8_t *pub, *sig, *msg; size_t publen, siglen, mlen;
    int verdict = 0;
    if (cmf_verify_parse(v->msg, v->msglen, &pub, &publen, &sig, &siglen, &msg, &mlen) == 0) {
        uint8_t d[WC_SHA256_DIGEST_SIZE];
        ecc_key key;
        if (wc_Sha256Hash(msg, (word32)mlen, d) == 0 && wc_ecc_init(&key) == 0) {
            int stat = 0;
            if (wc_ecc_import_x963(pub, (word32)publen, &key) == 0 &&
                wc_ecc_verify_hash(sig, (word32)siglen, d, sizeof d, &stat, &key) == 0)
                verdict = stat ? 1 : 0;
            wc_ecc_free(&key);
        }
    }
    out[0] = (uint8_t)verdict; *n = 1; return 0;
}

static int ed25519_sign(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    ed25519_key k;
    if (wc_ed25519_init(&k) != 0) return -1;
    uint8_t pub[ED25519_PUB_KEY_SIZE];
    word32 sl = CMF_ED25519_SIGLEN;
    int rc = -1;
    /* make_public writes the public key to the buffer but does not store it
     * inside the key object, so import it back before signing — otherwise the
     * signer hashes an all-zero public key and produces a wrong S. */
    if (wc_ed25519_import_private_only(v->key, CMF_KEYLEN, &k) == 0 &&
        wc_ed25519_make_public(&k, pub, sizeof pub) == 0 &&
        wc_ed25519_import_public(pub, sizeof pub, &k) == 0 &&
        wc_ed25519_sign_msg(v->msg, (word32)v->msglen, out, &sl, &k) == 0) {
        *n = sl; rc = 0;
    }
    wc_ed25519_free(&k);
    return rc;
}
static int x25519_ss(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    curve25519_key priv, peer;
    if (wc_curve25519_init(&priv) != 0) return -1;
    if (wc_curve25519_init(&peer) != 0) { wc_curve25519_free(&priv); return -1; }
    word32 sl = CMF_X25519_LEN;
    int rc = -1;
    /* This wolfSSL build enables curve25519 blinding, which requires an RNG on
     * the private key; without it shared_secret returns BAD_FUNC_ARG. Blinding
     * only randomizes intermediates — the shared secret is unchanged. */
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) { wc_curve25519_free(&peer); wc_curve25519_free(&priv); return -1; }
    if (wc_curve25519_import_private_ex(v->key, CMF_KEYLEN, &priv, EC25519_LITTLE_ENDIAN) == 0 &&
        wc_curve25519_import_public_ex(v->msg, CMF_X25519_LEN, &peer, EC25519_LITTLE_ENDIAN) == 0 &&
        wc_curve25519_set_rng(&priv, &rng) == 0 &&
        wc_curve25519_shared_secret_ex(&priv, &peer, out, &sl, EC25519_LITTLE_ENDIAN) == 0) {
        *n = sl; rc = 0;
    }
    wc_FreeRng(&rng);
    wc_curve25519_free(&peer);
    wc_curve25519_free(&priv);
    return rc;
}

static int hkdf(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (wc_HKDF(WC_SHA256, v->msg, (word32)v->msglen, v->key, CMF_KEYLEN,
                v->aad, (word32)v->aadlen, out, CMF_HKDF_OUTLEN) != 0) return -1;
    *n = CMF_HKDF_OUTLEN; return 0;
}
static int pbkdf2(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (wc_PBKDF2(out, v->msg, (int)v->msglen, v->key, CMF_KEYLEN,
                  CMF_PBKDF2_ITER, CMF_PBKDF2_DKLEN, WC_SHA256) != 0) return -1;
    *n = CMF_PBKDF2_DKLEN; return 0;
}

static int sha256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (wc_Sha256Hash(v->msg, (word32)v->msglen, out) != 0) return -1;
    *n = 32; return 0;
}

static int sha512(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (wc_Sha512Hash(v->msg, (word32)v->msglen, out) != 0) return -1;
    *n = 64; return 0;
}

static int sha3_256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (wc_Sha3_256Hash(v->msg, (word32)v->msglen, out) != 0) return -1;
    *n = 32; return 0;
}

static int sha3_512(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (wc_Sha3_512Hash(v->msg, (word32)v->msglen, out) != 0) return -1;
    *n = 64; return 0;
}

static int shake128(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    wc_Shake sk;
    if (wc_InitShake128(&sk, NULL, INVALID_DEVID) != 0) return -1;
    int rc = -1;
    if (wc_Shake128_Update(&sk, v->msg, (word32)v->msglen) == 0 &&
        wc_Shake128_Final(&sk, out, 32) == 0) { *n = 32; rc = 0; }
    wc_Shake128_Free(&sk);
    return rc;
}

static int shake256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    wc_Shake sk;
    if (wc_InitShake256(&sk, NULL, INVALID_DEVID) != 0) return -1;
    int rc = -1;
    if (wc_Shake256_Update(&sk, v->msg, (word32)v->msglen) == 0 &&
        wc_Shake256_Final(&sk, out, 64) == 0) { *n = 64; rc = 0; }
    wc_Shake256_Free(&sk);
    return rc;
}

static int hmac256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    Hmac h;
    if (wc_HmacInit(&h, NULL, INVALID_DEVID) != 0) return -1;
    int rc = -1;
    if (wc_HmacSetKey(&h, WC_SHA256, v->key, CMF_KEYLEN) == 0 &&
        wc_HmacUpdate(&h, v->msg, (word32)v->msglen) == 0 &&
        wc_HmacFinal(&h, out) == 0) { *n = 32; rc = 0; }
    wc_HmacFree(&h);
    return rc;
}

static int chachapoly(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    uint8_t tag[CMF_TAGLEN];
    if (wc_ChaCha20Poly1305_Encrypt(v->key, v->nonce, v->aad, (word32)v->aadlen,
                                    v->msg, (word32)v->msglen, out, tag) != 0)
        return -1;
    memcpy(out + v->msglen, tag, CMF_TAGLEN);
    *n = v->msglen + CMF_TAGLEN;
    return 0;
}

static int aesgcm(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    Aes aes;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return -1;
    uint8_t tag[CMF_TAGLEN];
    int rc = -1;
    if (wc_AesGcmSetKey(&aes, v->key, CMF_KEYLEN) == 0 &&
        wc_AesGcmEncrypt(&aes, out, v->msg, (word32)v->msglen,
                         v->nonce, CMF_NONCELEN, tag, CMF_TAGLEN,
                         v->aad, (word32)v->aadlen) == 0) {
        memcpy(out + v->msglen, tag, CMF_TAGLEN);
        *n = v->msglen + CMF_TAGLEN; rc = 0;
    }
    wc_AesFree(&aes);
    return rc;
}

int main(void) {
    char *line = NULL; size_t cap = 0; ssize_t len;
    uint8_t out[4096 + 64];
    while ((len = getline(&line, &cap, stdin)) > 0) {
        cmf_vec_t v; size_t n = 0; int rc = -1;
        if (cmf_vec_parse(line, &v) == 0) {
            switch (v.op) {
                case 0: rc = sha256(&v, out, &n); break;
                case 1: rc = sha512(&v, out, &n); break;
                case 2: rc = hmac256(&v, out, &n); break;
                case 3: rc = chachapoly(&v, out, &n); break;
                case 4: rc = aesgcm(&v, out, &n); break;
                case 5: rc = sha3_256(&v, out, &n); break;
                case 6: rc = sha3_512(&v, out, &n); break;
                case 7: rc = shake128(&v, out, &n); break;
                case 8: rc = shake256(&v, out, &n); break;
                case 9:  rc = hkdf(&v, out, &n); break;
                case 10: rc = pbkdf2(&v, out, &n); break;
                case 11: rc = ed25519_sign(&v, out, &n); break;
                case 12: rc = x25519_ss(&v, out, &n); break;
                case 13: rc = ecdsa_verify(&v, out, &n); break;
                case 14: rc = rsa_pss_verify(&v, out, &n); break;
                default: rc = -2; break;   /* ops 15+ not implemented here: abstain (NA) */
            }
            free(v.blob);
        }
        if (rc == -2) { printf("NA\n"); fflush(stdout); continue; }
        if (rc != 0) { printf("ERR\n"); fflush(stdout); continue; }
#ifdef CMF_DIFF_FAULT
        if (n) out[0] ^= 0xFF;   /* self-test: force a divergence */
#endif
        cmf_hexprint(out, n);
        fflush(stdout);
    }
    free(line);
    return 0;
}
