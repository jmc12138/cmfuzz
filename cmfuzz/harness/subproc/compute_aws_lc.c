/*
 * CMFuzz subprocess differential CLI — aws-lc backend (stage 2.1).
 *
 * Standalone binary linking ONLY aws-lc (never OpenSSL). aws-lc is AWS's fork of
 * BoringSSL, so it exposes the same one-shot EVP_AEAD API and redefines OpenSSL
 * symbols — hence the subprocess isolation. Reads request lines on stdin, prints
 * one hex output line per request. See compute_common.h for the wire protocol.
 *
 * CMF_DIFF_FAULT=1 flips the first output byte, so the differential runner's
 * negative self-test can prove it actually catches a divergent implementation.
 */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aead.h>
#include <openssl/hkdf.h>
#include <openssl/curve25519.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/nid.h>
#include "compute_common.h"

/* RSA-PSS verify-interop (op14): rebuild the public key from the raw modulus n
 * (exponent fixed at 65537), verify RSA-PSS(SHA-256, MGF1-SHA-256, salt=32) over
 * SHA-256(message); reply 1-byte accept/reject. */
static int rsa_pss_verify(const cmf_vec_t *v, uint8_t *out, size_t *n_out) {
    const uint8_t *pub, *sig, *msg; size_t publen, siglen, mlen;
    int verdict = 0;
    if (cmf_verify_parse(v->msg, v->msglen, &pub, &publen, &sig, &siglen, &msg, &mlen) == 0) {
        uint8_t d[32]; SHA256(msg, mlen, d);
        RSA *rsa = RSA_new();
        BIGNUM *n = BN_bin2bn(pub, publen, NULL);
        BIGNUM *e = BN_new();
        if (rsa && n && e && BN_set_word(e, CMF_RSA_PUB_E) &&
            RSA_set0_key(rsa, n, e, NULL)) {
            n = NULL; e = NULL;   /* ownership transferred to rsa */
            verdict = RSA_verify_pss_mgf1(rsa, d, sizeof d, EVP_sha256(),
                                          EVP_sha256(), CMF_RSA_SALTLEN,
                                          sig, siglen) == 1 ? 1 : 0;
        }
        BN_free(n); BN_free(e); RSA_free(rsa);
    }
    out[0] = (uint8_t)verdict; *n_out = 1; return 0;
}

/* ECDSA-P256 verify-interop (op13): import the SEC1 uncompressed public point,
 * verify the DER signature over SHA-256(message); reply 1-byte accept/reject. */
static int ecdsa_verify(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    const uint8_t *pub, *sig, *msg; size_t publen, siglen, mlen;
    int verdict = 0;
    if (cmf_verify_parse(v->msg, v->msglen, &pub, &publen, &sig, &siglen, &msg, &mlen) == 0) {
        uint8_t d[32]; SHA256(msg, mlen, d);
        EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (k) {
            const EC_GROUP *g = EC_KEY_get0_group(k);
            EC_POINT *pt = EC_POINT_new(g);
            if (pt && EC_POINT_oct2point(g, pt, pub, publen, NULL) == 1 &&
                EC_KEY_set_public_key(k, pt) == 1)
                verdict = ECDSA_verify(0, d, sizeof d, sig, siglen, k) == 1 ? 1 : 0;
            EC_POINT_free(pt); EC_KEY_free(k);
        }
    }
    out[0] = (uint8_t)verdict; *n = 1; return 0;
}

static int ed25519(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    uint8_t pub[32], priv[64];
    ED25519_keypair_from_seed(pub, priv, v->key);
    if (!ED25519_sign(out, v->msg, v->msglen, priv)) return -1;
    *n = CMF_ED25519_SIGLEN; return 0;
}
static int x25519(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (!X25519(out, v->key, v->msg)) return -1;
    *n = CMF_X25519_LEN; return 0;
}

static int hkdf(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (!HKDF(out, CMF_HKDF_OUTLEN, EVP_sha256(), v->msg, v->msglen,
              v->key, CMF_KEYLEN, v->aad, v->aadlen)) return -1;
    *n = CMF_HKDF_OUTLEN; return 0;
}
static int pbkdf2(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (!PKCS5_PBKDF2_HMAC((const char *)v->msg, v->msglen, v->key, CMF_KEYLEN,
                           CMF_PBKDF2_ITER, EVP_sha256(), CMF_PBKDF2_DKLEN, out))
        return -1;
    *n = CMF_PBKDF2_DKLEN; return 0;
}

static int digest(const EVP_MD *md, const cmf_vec_t *v, uint8_t *out, size_t *n) {
    unsigned int ol = 0;
    if (!EVP_Digest(v->msg, v->msglen, out, &ol, md, NULL)) return -1;
    *n = ol; return 0;
}

static int hmac256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    unsigned int ol = 0;
    if (!HMAC(EVP_sha256(), v->key, CMF_KEYLEN, v->msg, v->msglen, out, &ol)) return -1;
    *n = ol; return 0;
}

/* SHAKE XOF: squeeze a fixed number of bytes (see compute_common.h). */
static int xof(const EVP_MD *md, const cmf_vec_t *v, uint8_t *out, size_t outlen, size_t *n) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c) return -1;
    int ok = EVP_DigestInit_ex(c, md, NULL) &&
             EVP_DigestUpdate(c, v->msg, v->msglen) &&
             EVP_DigestFinalXOF(c, out, outlen);
    EVP_MD_CTX_free(c);
    if (!ok) return -1;
    *n = outlen; return 0;
}

static int aead(const EVP_AEAD *a, const cmf_vec_t *v, uint8_t *out, size_t *n) {
    EVP_AEAD_CTX *c = EVP_AEAD_CTX_new(a, v->key, EVP_AEAD_key_length(a),
                                       EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (!c) return -1;
    size_t ol = 0;
    int ok = EVP_AEAD_CTX_seal(c, out, &ol, v->msglen + CMF_TAGLEN,
                               v->nonce, CMF_NONCELEN, v->msg, v->msglen,
                               v->aad, v->aadlen);
    EVP_AEAD_CTX_free(c);
    if (!ok) return -1;
    *n = ol; return 0;
}

int main(void) {
    char *line = NULL; size_t cap = 0; ssize_t len;
    uint8_t out[4096 + 64];
    while ((len = getline(&line, &cap, stdin)) > 0) {
        cmf_vec_t v; size_t n = 0; int rc = -1;
        if (cmf_vec_parse(line, &v) == 0) {
            switch (v.op) {
                case 0: rc = digest(EVP_sha256(), &v, out, &n); break;
                case 1: rc = digest(EVP_sha512(), &v, out, &n); break;
                case 2: rc = hmac256(&v, out, &n); break;
                case 3: rc = aead(EVP_aead_chacha20_poly1305(), &v, out, &n); break;
                case 4: rc = aead(EVP_aead_aes_256_gcm(), &v, out, &n); break;
                case 5: rc = digest(EVP_sha3_256(), &v, out, &n); break;
                case 6: rc = digest(EVP_sha3_512(), &v, out, &n); break;
                case 7: rc = xof(EVP_shake128(), &v, out, 32, &n); break;
                case 8: rc = xof(EVP_shake256(), &v, out, 64, &n); break;
                case 9:  rc = hkdf(&v, out, &n); break;
                case 10: rc = pbkdf2(&v, out, &n); break;
                case 11: rc = ed25519(&v, out, &n); break;
                case 12: rc = x25519(&v, out, &n); break;
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
