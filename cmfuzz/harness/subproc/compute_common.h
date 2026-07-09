/*
 * Shared protocol for CMFuzz subprocess differential (stage 2.1).
 *
 * The differential runner (links OpenSSL as reference) drives one standalone
 * "compute CLI" per extra library as a child process. Libraries such as
 * BoringSSL / aws-lc redefine OpenSSL symbols and therefore cannot be linked
 * into the same process — isolating each behind a subprocess sidesteps every
 * symbol collision while still allowing a byte-exact differential.
 *
 * Wire protocol (line-based, stdin -> stdout):
 *   request : "<op> <hex>\n"   where hex = key(32) || nonce(12) ||
 *                              aadlen(2, big-endian) || aad || msg
 *   reply   : "<hex-output>\n" (digest, or ciphertext||tag for AEAD);
 *             "ERR\n" if the backend could not compute it;
 *             "NA\n"  if the backend does not implement this op (the runner
 *                     then skips it for that backend — not a divergence).
 *   ops     : 0 SHA-256  1 SHA-512  2 HMAC-SHA256
 *             3 ChaCha20-Poly1305(IETF)  4 AES-256-GCM
 *             5 SHA3-256  6 SHA3-512
 *             7 SHAKE128 (32-byte squeeze)  8 SHAKE256 (64-byte squeeze)
 *             9  HKDF-SHA256   (IKM=msg, salt=key, info=aad, 42-byte output)
 *             10 PBKDF2-HMAC-SHA256 (password=msg, salt=key, 4096 iters, 32B)
 *
 * Unused fields are ignored per op (hashes ignore key/nonce/aad; HMAC uses key
 * + msg; AEAD uses everything). Fixing the layout keeps one parser on both
 * sides, so agreement is by construction — any divergence is a real bug.
 */
#ifndef CMF_COMPUTE_COMMON_H
#define CMF_COMPUTE_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMF_KEYLEN   32
#define CMF_NONCELEN 12
#define CMF_TAGLEN   16

/* KDF differential parameters (ops 9/10) — fixed so agreement is by construction. */
#define CMF_HKDF_OUTLEN   42
#define CMF_PBKDF2_ITER   4096
#define CMF_PBKDF2_DKLEN  32

typedef struct {
    int      op;
    uint8_t  key[CMF_KEYLEN];
    uint8_t  nonce[CMF_NONCELEN];
    uint8_t *aad;   size_t aadlen;
    uint8_t *msg;   size_t msglen;
    uint8_t *blob;  /* backing store for aad/msg; caller frees */
} cmf_vec_t;

static inline int cmf_hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a hex string into a freshly malloc'd buffer; returns byte length. */
static inline uint8_t *cmf_hexdecode(const char *hex, size_t *outlen) {
    size_t hl = strlen(hex);
    while (hl && (hex[hl - 1] == '\n' || hex[hl - 1] == '\r' || hex[hl - 1] == ' '))
        hl--;
    size_t n = hl / 2;
    uint8_t *b = (uint8_t *)malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++) {
        int hi = cmf_hexval(hex[2 * i]), lo = cmf_hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(b); *outlen = 0; return NULL; }
        b[i] = (uint8_t)((hi << 4) | lo);
    }
    *outlen = n;
    return b;
}

static inline void cmf_hexprint(const uint8_t *b, size_t n) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { putchar(H[b[i] >> 4]); putchar(H[b[i] & 15]); }
    putchar('\n');
}

/* Parse one "<op> <hex>" request line into v. Returns 0 on success. */
static inline int cmf_vec_parse(char *line, cmf_vec_t *v) {
    memset(v, 0, sizeof *v);
    char *sp = strchr(line, ' ');
    if (!sp) return -1;
    *sp = '\0';
    v->op = atoi(line);
    size_t blen = 0;
    uint8_t *blob = cmf_hexdecode(sp + 1, &blen);
    if (!blob) return -1;
    v->blob = blob;
    size_t need = CMF_KEYLEN + CMF_NONCELEN + 2;
    if (blen < need) {          /* short blob: treat all of it as the message */
        v->msg = blob; v->msglen = blen;
        return 0;
    }
    memcpy(v->key, blob, CMF_KEYLEN);
    memcpy(v->nonce, blob + CMF_KEYLEN, CMF_NONCELEN);
    const uint8_t *p = blob + CMF_KEYLEN + CMF_NONCELEN;
    size_t aadlen = ((size_t)p[0] << 8) | p[1];
    p += 2;
    size_t rest = blen - need;
    if (aadlen > rest) aadlen = rest;
    v->aad = (uint8_t *)p; v->aadlen = aadlen;
    v->msg = (uint8_t *)p + aadlen; v->msglen = rest - aadlen;
    return 0;
}

#endif /* CMF_COMPUTE_COMMON_H */
