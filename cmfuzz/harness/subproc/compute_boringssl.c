/*
 * CMFuzz subprocess differential CLI — BoringSSL backend (stage 2.1).
 *
 * Standalone binary linking ONLY BoringSSL (never OpenSSL). Reads request
 * lines on stdin, prints one hex output line per request. See compute_common.h
 * for the wire protocol. AEAD uses BoringSSL's one-shot EVP_AEAD API (its own
 * state machine, distinct from OpenSSL's EVP_CIPHER update loop).
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
#include <openssl/sha.h>
#include <openssl/nid.h>
#include "compute_common.h"

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
                /* This BoringSSL build exposes no SHA-3/SHAKE via EVP. */
                case 5: case 6: case 7: case 8: rc = -2; break;
                case 9:  rc = hkdf(&v, out, &n); break;
                case 10: rc = pbkdf2(&v, out, &n); break;
                case 11: rc = ed25519(&v, out, &n); break;
                case 12: rc = x25519(&v, out, &n); break;
                case 13: rc = ecdsa_verify(&v, out, &n); break;
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
