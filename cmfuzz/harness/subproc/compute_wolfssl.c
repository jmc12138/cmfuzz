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
#include "compute_common.h"

static int sha256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (wc_Sha256Hash(v->msg, (word32)v->msglen, out) != 0) return -1;
    *n = 32; return 0;
}

static int sha512(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (wc_Sha512Hash(v->msg, (word32)v->msglen, out) != 0) return -1;
    *n = 64; return 0;
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
