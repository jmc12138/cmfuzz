/*
 * CMFuzz stage 3 subprocess differential CLI — libgcrypt backend.
 *
 * Standalone binary linking ONLY libgcrypt (GnuPG's crypto core), a genuinely
 * independent implementation with its own handle/S-expression API distinct from
 * OpenSSL's EVP. Behind a subprocess it gives a uniform byte-exact O1
 * differential (see compute_common.h for the wire protocol).
 *
 * Implemented ops: 0-8 (SHA-256/512, HMAC-SHA256, ChaCha20-Poly1305,
 * AES-256-GCM, SHA3-256/512, SHAKE128/256) and 10 (PBKDF2-HMAC-SHA256).
 * op 9 (HKDF) is absent from libgcrypt 1.9.x and the public-key ops 11-14
 * (Ed25519/X25519/ECDSA/RSA-PSS) use libgcrypt's involved S-expression API;
 * all of these reply "NA" so the runner skips them (not a divergence).
 *
 * CMF_DIFF_FAULT=1 flips the first output byte so the runner's negative
 * self-test can prove the differential catches a divergent implementation.
 */
#include <gcrypt.h>
#include "compute_common.h"

static int hash_buf(int algo, const cmf_vec_t *v, uint8_t *out, size_t *n) {
    unsigned int dl = gcry_md_get_algo_dlen(algo);
    gcry_md_hash_buffer(algo, out, v->msg, v->msglen);
    *n = dl; return 0;
}

static int shake(int algo, size_t outlen, const cmf_vec_t *v, uint8_t *out, size_t *n) {
    gcry_md_hd_t h;
    if (gcry_md_open(&h, algo, 0)) return -1;
    gcry_md_write(h, v->msg, v->msglen);
    gcry_error_t e = gcry_md_extract(h, algo, out, outlen);
    gcry_md_close(h);
    if (e) return -1;
    *n = outlen; return 0;
}

static int hmac_algo(int algo, const cmf_vec_t *v, uint8_t *out, size_t *n) {
    gcry_mac_hd_t h;
    if (gcry_mac_open(&h, algo, 0, NULL)) return -1;
    size_t ol = 64; int rc = -1;   /* fits the largest MAC we emit (SHA-512) */
    if (!gcry_mac_setkey(h, v->key, CMF_KEYLEN) &&
        !gcry_mac_write(h, v->msg, v->msglen) &&
        !gcry_mac_read(h, out, &ol)) { *n = ol; rc = 0; }
    gcry_mac_close(h);
    return rc;
}
static int hmac256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    return hmac_algo(GCRY_MAC_HMAC_SHA256, v, out, n);
}

static int aead_kl(int cipher, int mode, size_t keylen,
                   const cmf_vec_t *v, uint8_t *out, size_t *n) {
    gcry_cipher_hd_t h;
    if (gcry_cipher_open(&h, cipher, mode, 0)) return -1;
    int rc = -1;
    if (!gcry_cipher_setkey(h, v->key, keylen) &&
        !gcry_cipher_setiv(h, v->nonce, CMF_NONCELEN) &&
        (v->aadlen == 0 || !gcry_cipher_authenticate(h, v->aad, v->aadlen)) &&
        !gcry_cipher_encrypt(h, out, v->msglen, v->msg, v->msglen) &&
        !gcry_cipher_gettag(h, out + v->msglen, CMF_TAGLEN)) {
        *n = v->msglen + CMF_TAGLEN; rc = 0;
    }
    gcry_cipher_close(h);
    return rc;
}
static int aead(int cipher, int mode, const cmf_vec_t *v, uint8_t *out, size_t *n) {
    return aead_kl(cipher, mode, CMF_KEYLEN, v, out, n);
}

static int pbkdf2(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    if (gcry_kdf_derive(v->msg, v->msglen, GCRY_KDF_PBKDF2, GCRY_MD_SHA256,
                        v->key, CMF_KEYLEN, CMF_PBKDF2_ITER,
                        CMF_PBKDF2_DKLEN, out)) return -1;
    *n = CMF_PBKDF2_DKLEN; return 0;
}

int main(void) {
    if (!gcry_check_version(NULL)) { fprintf(stderr, "libgcrypt init failed\n"); return 2; }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    char *line = NULL; size_t cap = 0; ssize_t len;
    uint8_t out[8192];
    while ((len = getline(&line, &cap, stdin)) > 0) {
        cmf_vec_t v; size_t n = 0; int rc = -1; int na = 0;
        if (cmf_vec_parse(line, &v) == 0) {
            switch (v.op) {
                case 0:  rc = hash_buf(GCRY_MD_SHA256, &v, out, &n); break;
                case 1:  rc = hash_buf(GCRY_MD_SHA512, &v, out, &n); break;
                case 2:  rc = hmac256(&v, out, &n); break;
                case 3:  rc = aead(GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, &v, out, &n); break;
                case 4:  rc = aead(GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, &v, out, &n); break;
                case 5:  rc = hash_buf(GCRY_MD_SHA3_256, &v, out, &n); break;
                case 6:  rc = hash_buf(GCRY_MD_SHA3_512, &v, out, &n); break;
                case 7:  rc = shake(GCRY_MD_SHAKE128, 32, &v, out, &n); break;
                case 8:  rc = shake(GCRY_MD_SHAKE256, 64, &v, out, &n); break;
                case 10: rc = pbkdf2(&v, out, &n); break;
                /* Extra digest coverage (blind-spot A). */
                case 15: rc = hash_buf(GCRY_MD_SHA1, &v, out, &n); break;
                case 16: rc = hash_buf(GCRY_MD_SHA224, &v, out, &n); break;
                case 17: rc = hash_buf(GCRY_MD_SHA384, &v, out, &n); break;
                case 18: rc = hash_buf(GCRY_MD_SHA512_256, &v, out, &n); break;
                case 19: rc = hash_buf(GCRY_MD_MD5, &v, out, &n); break;
                /* Extra HMAC coverage (blind-spot A). */
                case 20: rc = hmac_algo(GCRY_MAC_HMAC_SHA1, &v, out, &n); break;
                case 21: rc = hmac_algo(GCRY_MAC_HMAC_SHA384, &v, out, &n); break;
                case 22: rc = hmac_algo(GCRY_MAC_HMAC_SHA512, &v, out, &n); break;
                /* Extra AEAD / MAC coverage (blind-spot A). Poly1305 (op25) uses
                 * a 32-byte one-time key; CMAC with a 32-byte key is AES-256. */
                case 23: rc = aead_kl(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 16, &v, out, &n); break;
                case 24: rc = aead_kl(GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM, 24, &v, out, &n); break;
                case 25: rc = hmac_algo(GCRY_MAC_POLY1305, &v, out, &n); break;
                case 26: rc = hmac_algo(GCRY_MAC_CMAC_AES, &v, out, &n); break;
                default: na = 1; break;   /* 9 (HKDF), 11-14 (public-key): NA */
            }
            free(v.blob);
        }
        if (na) { printf("NA\n"); fflush(stdout); continue; }
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
