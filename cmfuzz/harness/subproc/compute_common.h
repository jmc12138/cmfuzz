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
 *             11 Ed25519 sign  (seed=key, message=msg -> 64-byte signature;
 *                               deterministic per RFC 8032, so byte-exact)
 *             12 X25519        (scalar=key, peer public=msg[0..32] -> 32-byte
 *                               shared secret; deterministic per RFC 7748)
 *             13 ECDSA-P256 verify (verify-interop oracle: the reference/OpenSSL
 *                               generates a P-256 key + ECDSA-SHA256 signature,
 *                               sometimes tampered; each backend replies with a
 *                               1-byte verdict 01=accept / 00=reject, and all
 *                               backends must agree on the verdict. The msg
 *                               region carries a verify-payload, see below.)
 *             14 RSA-PSS verify (verify-interop oracle: reference/OpenSSL RSA-2048
 *                               key, RSA-PSS(SHA-256, MGF1-SHA-256, salt=32)
 *                               signature, sometimes tampered. The "pubkey" field
 *                               of the verify-payload is the raw modulus n; the
 *                               public exponent is fixed at 65537. Same 1-byte
 *                               accept/reject verdict comparison as op13.)
 *             15 SHA-1  16 SHA-224  17 SHA-384  18 SHA-512/256  19 MD5
 *                               (extra digest coverage; ignore key/nonce/aad)
 *
 * Verify-payload (ops >= 13, packed inside the msg region):
 *     pubkeylen(2, BE) || pubkey || siglen(2, BE) || sig || message
 *   Randomised schemes (ECDSA k) don't break the differential because only the
 *   accept/reject verdict is compared, not signature bytes. This also exercises
 *   cross-library key/signature encoding parsing (SEC1 point, ASN.1 DER).
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

/* Public-key differential parameters (ops 11/12) — deterministic primitives. */
#define CMF_ED25519_SIGLEN 64
#define CMF_X25519_LEN     32

/* RSA-PSS verify-interop (op14): fixed public exponent + PSS salt length so the
 * verdict is well-defined across libraries. */
#define CMF_RSA_PUB_E   65537
#define CMF_RSA_SALTLEN 32

/* Verify-interop ops (>= 13): parse the packed verify-payload out of the msg
 * region into (public key, signature, message) views. Returns 0 on success. */
static inline int cmf_verify_parse(const uint8_t *p, size_t plen,
                                   const uint8_t **pub, size_t *publen,
                                   const uint8_t **sig, size_t *siglen,
                                   const uint8_t **msg, size_t *msglen) {
    size_t off = 0;
    if (plen < 2) return -1;
    size_t pl = ((size_t)p[0] << 8) | p[1]; off = 2;
    if (off + pl + 2 > plen) return -1;
    *pub = p + off; *publen = pl; off += pl;
    size_t sl = ((size_t)p[off] << 8) | p[off + 1]; off += 2;
    if (off + sl > plen) return -1;
    *sig = p + off; *siglen = sl; off += sl;
    *msg = p + off; *msglen = plen - off;
    return 0;
}

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
