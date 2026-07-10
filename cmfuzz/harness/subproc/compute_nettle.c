/*
 * CMFuzz stage 3 subprocess differential CLI — GnuTLS nettle backend.
 *
 * Standalone binary linking ONLY nettle, an independent low-level crypto library
 * (GnuTLS's core) with a per-primitive context API distinct from OpenSSL's EVP.
 * Behind a subprocess it yields a uniform byte-exact O1 differential
 * (see compute_common.h for the wire protocol).
 *
 * Implemented ops: 0-6, 8-12
 *   0/1 SHA-256/512, 2 HMAC-SHA256, 3 ChaCha20-Poly1305, 4 AES-256-GCM,
 *   5/6 SHA3-256/512, 8 SHAKE256, 9 HKDF-SHA256, 10 PBKDF2-HMAC-SHA256,
 *   11 Ed25519 sign, 12 X25519.
 * op 7 (SHAKE128) is absent from nettle 3.7 (only the SHA3-256-rate SHAKE256 is
 * provided) and ops 13/14 (ECDSA/RSA-PSS verify) need nettle's GMP-based hogweed
 * DER handling; all of these reply "NA" so the runner skips them.
 *
 * CMF_DIFF_FAULT=1 flips the first output byte for the negative self-test.
 */
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include <nettle/sha3.h>
#include <nettle/md5.h>
#include <nettle/hmac.h>
#include <nettle/chacha-poly1305.h>
#include <nettle/gcm.h>
#include <nettle/aes.h>
#include <nettle/pbkdf2.h>
#include <nettle/hkdf.h>
#include <nettle/eddsa.h>
#include <nettle/curve25519.h>
#include "compute_common.h"

static int sha256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct sha256_ctx c; sha256_init(&c);
    sha256_update(&c, v->msglen, v->msg);
    sha256_digest(&c, SHA256_DIGEST_SIZE, out);
    *n = SHA256_DIGEST_SIZE; return 0;
}
static int sha512(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct sha512_ctx c; sha512_init(&c);
    sha512_update(&c, v->msglen, v->msg);
    sha512_digest(&c, SHA512_DIGEST_SIZE, out);
    *n = SHA512_DIGEST_SIZE; return 0;
}
static int sha3_256_(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct sha3_256_ctx c; sha3_256_init(&c);
    sha3_256_update(&c, v->msglen, v->msg);
    sha3_256_digest(&c, SHA3_256_DIGEST_SIZE, out);
    *n = SHA3_256_DIGEST_SIZE; return 0;
}
static int sha3_512_(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct sha3_512_ctx c; sha3_512_init(&c);
    sha3_512_update(&c, v->msglen, v->msg);
    sha3_512_digest(&c, SHA3_512_DIGEST_SIZE, out);
    *n = SHA3_512_DIGEST_SIZE; return 0;
}
static int shake256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct sha3_256_ctx c; sha3_256_init(&c);
    sha3_256_update(&c, v->msglen, v->msg);
    sha3_256_shake(&c, 64, out);
    *n = 64; return 0;
}
/* Extra digests (blind-spot A). nettle exposes SHA-224/384/512-256 via the
 * SHA-256/512 context types (see sha2.h), plus standalone SHA-1 and MD5. */
static int nsha1(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct sha1_ctx c; sha1_init(&c);
    sha1_update(&c, v->msglen, v->msg);
    sha1_digest(&c, SHA1_DIGEST_SIZE, out);
    *n = SHA1_DIGEST_SIZE; return 0;
}
static int nsha224(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct sha256_ctx c; sha224_init(&c);
    sha224_update(&c, v->msglen, v->msg);
    sha224_digest(&c, SHA224_DIGEST_SIZE, out);
    *n = SHA224_DIGEST_SIZE; return 0;
}
static int nsha384(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct sha512_ctx c; sha384_init(&c);
    sha384_update(&c, v->msglen, v->msg);
    sha384_digest(&c, SHA384_DIGEST_SIZE, out);
    *n = SHA384_DIGEST_SIZE; return 0;
}
static int nsha512_256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct sha512_256_ctx c; sha512_256_init(&c);
    sha512_256_update(&c, v->msglen, v->msg);
    sha512_256_digest(&c, SHA512_256_DIGEST_SIZE, out);
    *n = SHA512_256_DIGEST_SIZE; return 0;
}
static int nmd5(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct md5_ctx c; md5_init(&c);
    md5_update(&c, v->msglen, v->msg);
    md5_digest(&c, MD5_DIGEST_SIZE, out);
    *n = MD5_DIGEST_SIZE; return 0;
}
static int hmac256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct hmac_sha256_ctx c;
    hmac_sha256_set_key(&c, CMF_KEYLEN, v->key);
    hmac_sha256_update(&c, v->msglen, v->msg);
    hmac_sha256_digest(&c, SHA256_DIGEST_SIZE, out);
    *n = SHA256_DIGEST_SIZE; return 0;
}
/* Extra HMAC coverage (blind-spot A). nettle's SHA-384 HMAC reuses the
 * SHA-512 context type (see hmac.h). */
static int hmac1(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct hmac_sha1_ctx c;
    hmac_sha1_set_key(&c, CMF_KEYLEN, v->key);
    hmac_sha1_update(&c, v->msglen, v->msg);
    hmac_sha1_digest(&c, SHA1_DIGEST_SIZE, out);
    *n = SHA1_DIGEST_SIZE; return 0;
}
static int hmac384(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct hmac_sha512_ctx c;
    hmac_sha384_set_key(&c, CMF_KEYLEN, v->key);
    hmac_sha384_update(&c, v->msglen, v->msg);
    hmac_sha384_digest(&c, SHA384_DIGEST_SIZE, out);
    *n = SHA384_DIGEST_SIZE; return 0;
}
static int hmac512(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct hmac_sha512_ctx c;
    hmac_sha512_set_key(&c, CMF_KEYLEN, v->key);
    hmac_sha512_update(&c, v->msglen, v->msg);
    hmac_sha512_digest(&c, SHA512_DIGEST_SIZE, out);
    *n = SHA512_DIGEST_SIZE; return 0;
}
static int chachapoly(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct chacha_poly1305_ctx c;
    chacha_poly1305_set_key(&c, v->key);
    chacha_poly1305_set_nonce(&c, v->nonce);
    if (v->aadlen) chacha_poly1305_update(&c, v->aadlen, v->aad);
    chacha_poly1305_encrypt(&c, v->msglen, out, v->msg);
    chacha_poly1305_digest(&c, CHACHA_POLY1305_DIGEST_SIZE, out + v->msglen);
    *n = v->msglen + CHACHA_POLY1305_DIGEST_SIZE; return 0;
}
static int aesgcm(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    struct gcm_aes256_ctx c;
    gcm_aes256_set_key(&c, v->key);
    gcm_aes256_set_iv(&c, CMF_NONCELEN, v->nonce);
    if (v->aadlen) gcm_aes256_update(&c, v->aadlen, v->aad);
    gcm_aes256_encrypt(&c, v->msglen, out, v->msg);
    gcm_aes256_digest(&c, CMF_TAGLEN, out + v->msglen);
    *n = v->msglen + CMF_TAGLEN; return 0;
}
static int pbkdf2_(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    pbkdf2_hmac_sha256(v->msglen, v->msg, CMF_PBKDF2_ITER,
                       CMF_KEYLEN, v->key, CMF_PBKDF2_DKLEN, out);
    *n = CMF_PBKDF2_DKLEN; return 0;
}
static int hkdf_(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    /* HKDF-SHA256: IKM=msg, salt=key, info=aad, 42-byte output. */
    struct hmac_sha256_ctx c;
    uint8_t prk[SHA256_DIGEST_SIZE];
    hmac_sha256_set_key(&c, CMF_KEYLEN, v->key);   /* salt */
    hkdf_extract(&c, (nettle_hash_update_func *)hmac_sha256_update,
                 (nettle_hash_digest_func *)hmac_sha256_digest,
                 SHA256_DIGEST_SIZE, v->msglen, v->msg, prk);
    hmac_sha256_set_key(&c, SHA256_DIGEST_SIZE, prk);
    hkdf_expand(&c, (nettle_hash_update_func *)hmac_sha256_update,
                (nettle_hash_digest_func *)hmac_sha256_digest,
                SHA256_DIGEST_SIZE, v->aadlen, v->aad, CMF_HKDF_OUTLEN, out);
    *n = CMF_HKDF_OUTLEN; return 0;
}
static int ed25519_(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    uint8_t pub[ED25519_KEY_SIZE];
    ed25519_sha512_public_key(pub, v->key);
    ed25519_sha512_sign(pub, v->key, v->msglen, v->msg, out);
    *n = ED25519_SIGNATURE_SIZE; return 0;
}
static int x25519_(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    uint8_t scalar[CURVE25519_SIZE];
    memcpy(scalar, v->key, CURVE25519_SIZE);
    scalar[0] &= 248; scalar[31] &= 127; scalar[31] |= 64;   /* RFC 7748 clamp */
    curve25519_mul(out, scalar, v->msg);
    *n = CURVE25519_SIZE; return 0;
}

int main(void) {
    char *line = NULL; size_t cap = 0; ssize_t len;
    uint8_t out[8192];
    while ((len = getline(&line, &cap, stdin)) > 0) {
        cmf_vec_t v; size_t n = 0; int rc = -1; int na = 0;
        if (cmf_vec_parse(line, &v) == 0) {
            switch (v.op) {
                case 0:  rc = sha256(&v, out, &n); break;
                case 1:  rc = sha512(&v, out, &n); break;
                case 2:  rc = hmac256(&v, out, &n); break;
                case 3:  rc = chachapoly(&v, out, &n); break;
                case 4:  rc = aesgcm(&v, out, &n); break;
                case 5:  rc = sha3_256_(&v, out, &n); break;
                case 6:  rc = sha3_512_(&v, out, &n); break;
                case 8:  rc = shake256(&v, out, &n); break;
                case 9:  rc = hkdf_(&v, out, &n); break;
                case 10: rc = pbkdf2_(&v, out, &n); break;
                case 11: rc = ed25519_(&v, out, &n); break;
                case 12: rc = x25519_(&v, out, &n); break;
                case 15: rc = nsha1(&v, out, &n); break;
                case 16: rc = nsha224(&v, out, &n); break;
                case 17: rc = nsha384(&v, out, &n); break;
                case 18: rc = nsha512_256(&v, out, &n); break;
                case 19: rc = nmd5(&v, out, &n); break;
                case 20: rc = hmac1(&v, out, &n); break;
                case 21: rc = hmac384(&v, out, &n); break;
                case 22: rc = hmac512(&v, out, &n); break;
                default: na = 1; break;   /* 7 (SHAKE128), 13/14: NA */
            }
            free(v.blob);
        }
        if (na) { printf("NA\n"); fflush(stdout); continue; }
        if (rc != 0) { printf("ERR\n"); fflush(stdout); continue; }
#ifdef CMF_DIFF_FAULT
        if (n) out[0] ^= 0xFF;
#endif
        cmf_hexprint(out, n);
        fflush(stdout);
    }
    free(line);
    return 0;
}
