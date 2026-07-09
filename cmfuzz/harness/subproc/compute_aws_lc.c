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
#include "compute_common.h"

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
            }
            free(v.blob);
        }
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
