/*
 * CMFuzz subprocess differential runner (stage 2.1).
 *
 * Reference implementation = in-process OpenSSL. Each extra backend
 * (BoringSSL / aws-lc / wolfCrypt / Botan) is a standalone compute CLI driven
 * as a batched child process (see compute_common.h). This sidesteps the
 * OpenSSL-symbol collisions that make in-process linking impossible, while
 * still giving a byte-exact O1 differential across libraries.
 *
 * Usage:  diff_subproc_runner <n> <seed> <name=path> [<name=path> ...]
 *   Generates <n> deterministic random test vectors (5 primitives), computes
 *   the OpenSSL reference for each, then feeds all requests to every backend
 *   and checks the backend agrees byte-for-byte. Any divergence prints a
 *   CMF_VIOLATION line and exits non-zero (so it doubles as a self-test when a
 *   fault-injected CLI is passed).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include "compute_common.h"

/* -------- deterministic PRNG (splitmix64) for reproducible vectors -------- */
static uint64_t g_state;
static uint64_t rnd(void) {
    uint64_t z = (g_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void rnd_bytes(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(rnd() & 0xFF);
}

/* ------------------------- OpenSSL reference ------------------------- */
static int ref_digest(const EVP_MD *md, const cmf_vec_t *v, uint8_t *o, size_t *n) {
    unsigned int ol = 0;
    if (!EVP_Digest(v->msg, v->msglen, o, &ol, md, NULL)) return -1;
    *n = ol; return 0;
}
/* SHAKE is an XOF: squeeze a fixed number of bytes so the differential is
 * well-defined (SHAKE128 -> 32 bytes, SHAKE256 -> 64 bytes). */
static int ref_xof(const EVP_MD *md, const cmf_vec_t *v, uint8_t *o, size_t outlen, size_t *n) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c) return -1;
    int ok = EVP_DigestInit_ex(c, md, NULL) &&
             EVP_DigestUpdate(c, v->msg, v->msglen) &&
             EVP_DigestFinalXOF(c, o, outlen);
    EVP_MD_CTX_free(c);
    if (!ok) return -1;
    *n = outlen; return 0;
}
static int ref_hmac(const cmf_vec_t *v, uint8_t *o, size_t *n) {
    unsigned int ol = 0;
    if (!HMAC(EVP_sha256(), v->key, CMF_KEYLEN, v->msg, v->msglen, o, &ol)) return -1;
    *n = ol; return 0;
}
static int ref_aead(const EVP_CIPHER *ci, const cmf_vec_t *v, uint8_t *o, size_t *n) {
    int len = 0, cl = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    EVP_EncryptInit_ex(c, ci, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, CMF_NONCELEN, NULL);
    EVP_EncryptInit_ex(c, NULL, NULL, v->key, v->nonce);
    if (v->aadlen) EVP_EncryptUpdate(c, NULL, &len, v->aad, (int)v->aadlen);
    EVP_EncryptUpdate(c, o, &len, v->msg, (int)v->msglen); cl = len;
    EVP_EncryptFinal_ex(c, o + cl, &len); cl += len;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, CMF_TAGLEN, o + cl); cl += CMF_TAGLEN;
    EVP_CIPHER_CTX_free(c);
    *n = (size_t)cl; return 0;
}
static int ref_hkdf(const cmf_vec_t *v, uint8_t *o, size_t *n) {
    EVP_KDF *k = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!k) return -1;
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(k);
    EVP_KDF_free(k);
    if (!c) return -1;
    OSSL_PARAM p[5]; int i = 0;
    p[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)v->msg, v->msglen);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)v->key, CMF_KEYLEN);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)v->aad, v->aadlen);
    p[i]   = OSSL_PARAM_construct_end();
    int ok = EVP_KDF_derive(c, o, CMF_HKDF_OUTLEN, p);
    EVP_KDF_CTX_free(c);
    if (ok <= 0) return -1;
    *n = CMF_HKDF_OUTLEN; return 0;
}
static int ref_pbkdf2(const cmf_vec_t *v, uint8_t *o, size_t *n) {
    if (!PKCS5_PBKDF2_HMAC((const char *)v->msg, (int)v->msglen,
                           v->key, CMF_KEYLEN, CMF_PBKDF2_ITER,
                           EVP_sha256(), CMF_PBKDF2_DKLEN, o)) return -1;
    *n = CMF_PBKDF2_DKLEN; return 0;
}
static int ref_ed25519(const cmf_vec_t *v, uint8_t *o, size_t *n) {
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, v->key, CMF_KEYLEN);
    if (!pk) return -1;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    size_t sl = CMF_ED25519_SIGLEN;
    int ok = c && EVP_DigestSignInit(c, NULL, NULL, NULL, pk) == 1 &&
             EVP_DigestSign(c, o, &sl, v->msg, v->msglen) == 1;
    EVP_MD_CTX_free(c); EVP_PKEY_free(pk);
    if (!ok) return -1;
    *n = sl; return 0;
}
static int ref_x25519(const cmf_vec_t *v, uint8_t *o, size_t *n) {
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, v->key, CMF_KEYLEN);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, v->msg, CMF_X25519_LEN);
    EVP_PKEY_CTX *ctx = priv ? EVP_PKEY_CTX_new(priv, NULL) : NULL;
    size_t sl = CMF_X25519_LEN;
    int ok = priv && peer && ctx &&
             EVP_PKEY_derive_init(ctx) == 1 &&
             EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
             EVP_PKEY_derive(ctx, o, &sl) == 1;
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(peer); EVP_PKEY_free(priv);
    if (!ok) return -1;
    *n = sl; return 0;
}
/* ECDSA-P256 verify-interop (op13): OpenSSL is both the signer (reference) and
 * the verdict authority. One P-256 key is reused for the whole run (only the
 * message and the tamper decision vary). Produces the verify-payload
 * (pubkeylen||pub||siglen||sig||message) and the accept/reject verdict OpenSSL
 * assigns to it, which every backend must reproduce. */
static EVP_PKEY *g_ecdsa_key = NULL;
static int ecdsa_make_payload(uint8_t *pl, size_t *plen, int *verdict) {
    if (!g_ecdsa_key) g_ecdsa_key = EVP_EC_gen("P-256");
    if (!g_ecdsa_key) return -1;
    size_t mlen = 1 + (rnd() % 200);
    uint8_t msg[256];
    for (size_t i = 0; i < mlen; i++) msg[i] = (uint8_t)(rnd() & 0xFF);
    uint8_t sig[160]; size_t siglen = sizeof sig;
    EVP_MD_CTX *sc = EVP_MD_CTX_new();
    int signed_ok = sc &&
        EVP_DigestSignInit(sc, NULL, EVP_sha256(), NULL, g_ecdsa_key) == 1 &&
        EVP_DigestSign(sc, sig, &siglen, msg, mlen) == 1;
    EVP_MD_CTX_free(sc);
    if (!signed_ok) return -1;
    /* Stronger tampering (blind-spot C): on ~half the vectors flip a random bit
     * in EITHER the message OR the signature before the verdict is computed, so
     * backends' reject paths are exercised for both a content change and a
     * malformed/invalid signature (not just a message edit). */
    if (rnd() & 1) {
        if (rnd() & 1) msg[rnd() % mlen]    ^= (uint8_t)(1u << (rnd() % 8));
        else           sig[rnd() % siglen] ^= (uint8_t)(1u << (rnd() % 8));
    }
    EVP_MD_CTX *vc = EVP_MD_CTX_new();
    *verdict = (vc &&
        EVP_DigestVerifyInit(vc, NULL, EVP_sha256(), NULL, g_ecdsa_key) == 1 &&
        EVP_DigestVerify(vc, sig, siglen, msg, mlen) == 1) ? 1 : 0;
    EVP_MD_CTX_free(vc);
    uint8_t *pub = NULL;
    size_t publen = EVP_PKEY_get1_encoded_public_key(g_ecdsa_key, &pub);
    if (!pub || publen == 0) return -1;
    size_t off = 0;
    pl[off++] = (uint8_t)(publen >> 8); pl[off++] = (uint8_t)(publen & 0xFF);
    memcpy(pl + off, pub, publen); off += publen;
    pl[off++] = (uint8_t)(siglen >> 8); pl[off++] = (uint8_t)(siglen & 0xFF);
    memcpy(pl + off, sig, siglen); off += siglen;
    memcpy(pl + off, msg, mlen); off += mlen;
    OPENSSL_free(pub);
    *plen = off; return 0;
}

/* RSA-PSS verify-interop (op14): one RSA-2048 key is reused for the whole run
 * (keygen is expensive). OpenSSL signs with RSA-PSS(SHA-256, MGF1-SHA-256,
 * salt=32), tampers the message on ~half the vectors, and records the verdict.
 * The verify-payload's "pubkey" field is the raw modulus n (public exponent is
 * fixed at 65537, so it need not be transmitted). */
static EVP_PKEY *g_rsa_key = NULL;
static int rsa_pss_sign_or_verify(int sign, uint8_t *sig, size_t *siglen,
                                  const uint8_t *msg, size_t mlen) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c) return -1;
    EVP_PKEY_CTX *pctx = NULL;
    int ok;
    if (sign)
        ok = EVP_DigestSignInit(c, &pctx, EVP_sha256(), NULL, g_rsa_key) == 1;
    else
        ok = EVP_DigestVerifyInit(c, &pctx, EVP_sha256(), NULL, g_rsa_key) == 1;
    ok = ok &&
         EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
         EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, CMF_RSA_SALTLEN) == 1 &&
         EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) == 1;
    if (ok) {
        if (sign) ok = EVP_DigestSign(c, sig, siglen, msg, mlen) == 1;
        else      ok = EVP_DigestVerify(c, sig, *siglen, msg, mlen) == 1;
    }
    EVP_MD_CTX_free(c);
    return ok ? 0 : -1;
}
static int rsa_make_payload(uint8_t *pl, size_t *plen, int *verdict) {
    if (!g_rsa_key) g_rsa_key = EVP_RSA_gen(2048);
    if (!g_rsa_key) return -1;
    size_t mlen = 1 + (rnd() % 200);
    uint8_t msg[256];
    for (size_t i = 0; i < mlen; i++) msg[i] = (uint8_t)(rnd() & 0xFF);
    uint8_t sig[512]; size_t siglen = sizeof sig;
    if (rsa_pss_sign_or_verify(1, sig, &siglen, msg, mlen) != 0) return -1;
    /* Stronger tampering (blind-spot C): flip a random bit in the message OR the
     * signature before computing the verdict. */
    if (rnd() & 1) {
        if (rnd() & 1) msg[rnd() % mlen]    ^= (uint8_t)(1u << (rnd() % 8));
        else           sig[rnd() % siglen] ^= (uint8_t)(1u << (rnd() % 8));
    }
    *verdict = (rsa_pss_sign_or_verify(0, sig, &siglen, msg, mlen) == 0) ? 1 : 0;
    BIGNUM *bn = NULL;
    if (EVP_PKEY_get_bn_param(g_rsa_key, OSSL_PKEY_PARAM_RSA_N, &bn) != 1 || !bn) return -1;
    uint8_t nbuf[512]; int nlen = BN_bn2bin(bn, nbuf);
    BN_free(bn);
    if (nlen <= 0) return -1;
    size_t off = 0;
    pl[off++] = (uint8_t)((size_t)nlen >> 8); pl[off++] = (uint8_t)((size_t)nlen & 0xFF);
    memcpy(pl + off, nbuf, (size_t)nlen); off += (size_t)nlen;
    pl[off++] = (uint8_t)(siglen >> 8); pl[off++] = (uint8_t)(siglen & 0xFF);
    memcpy(pl + off, sig, siglen); off += siglen;
    memcpy(pl + off, msg, mlen); off += mlen;
    *plen = off; return 0;
}

static int ref_compute(const cmf_vec_t *v, uint8_t *o, size_t *n) {
    switch (v->op) {
        case 0: return ref_digest(EVP_sha256(), v, o, n);
        case 1: return ref_digest(EVP_sha512(), v, o, n);
        case 2: return ref_hmac(v, o, n);
        case 3: return ref_aead(EVP_chacha20_poly1305(), v, o, n);
        case 4: return ref_aead(EVP_aes_256_gcm(), v, o, n);
        case 5: return ref_digest(EVP_sha3_256(), v, o, n);
        case 6: return ref_digest(EVP_sha3_512(), v, o, n);
        case 7: return ref_xof(EVP_shake128(), v, o, 32, n);
        case 8: return ref_xof(EVP_shake256(), v, o, 64, n);
        case 9: return ref_hkdf(v, o, n);
        case 10: return ref_pbkdf2(v, o, n);
        case 11: return ref_ed25519(v, o, n);
        case 12: return ref_x25519(v, o, n);
        /* Extra digest coverage (blind-spot A): more of the SHA-2 family plus
         * the legacy SHA-1/MD5 that real deployments still emit. */
        case 15: return ref_digest(EVP_sha1(), v, o, n);
        case 16: return ref_digest(EVP_sha224(), v, o, n);
        case 17: return ref_digest(EVP_sha384(), v, o, n);
        case 18: return ref_digest(EVP_sha512_256(), v, o, n);
        case 19: return ref_digest(EVP_md5(), v, o, n);
    }
    return -1;
}

/* ops 0..19 excluding the verify ops' special handling (see compute_common.h) */
#define CMF_NUM_OPS 20

static const char *HEX = "0123456789abcdef";
static void tohex(const uint8_t *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) { out[2*i] = HEX[b[i]>>4]; out[2*i+1] = HEX[b[i]&15]; }
    out[2*n] = '\0';
}

/* Adversarial X25519 peer u-coordinates (blind-spot B): the classic low-order
 * points (orders 1/2/4/8) and the field-boundary values p-1, p, p+1. Each drives
 * the scalar multiplication into its degenerate case, which random fuzzing
 * effectively never reaches. RFC 7748 lets an implementation EITHER return the
 * resulting all-zero shared secret OR raise an error, so these are not by
 * themselves divergences: x25519_normalize() folds "all-zero secret" and "ERR"
 * to one verdict before comparison (little-endian, per RFC 7748). */
static const uint8_t X25519_EDGE[][CMF_X25519_LEN] = {
    /* u = 0 (order 1) */
    {0x00},
    /* u = 1 (order 1) */
    {0x01},
    /* order-8 point */
    {0xe0,0xeb,0x7a,0x7c,0x3b,0x41,0xb8,0xae,0x16,0x56,0xe3,0xfa,0xf1,0x9f,0xc4,0x6a,
     0xda,0x09,0x8d,0xeb,0x9c,0x32,0xb1,0xfd,0x86,0x62,0x05,0x16,0x5f,0x49,0xb8,0x00},
    /* order-8 point */
    {0x5f,0x9c,0x95,0xbc,0xa3,0x50,0x8c,0x24,0xb1,0xd0,0xb1,0x55,0x9c,0x83,0xef,0x5b,
     0x04,0x44,0x5c,0xc4,0x58,0x1c,0x8e,0x86,0xd8,0x22,0x4e,0xdd,0xd0,0x9f,0x11,0x57},
    /* p-1 */
    {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* p */
    {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* p+1 */
    {0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    /* all-ones (non-canonical; the top bit is masked to canonical form) */
    {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
     0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
};
#define X25519_EDGE_N (sizeof X25519_EDGE / sizeof X25519_EDGE[0])

/* Boundary message lengths (blind-spot B): block/limb edges that block ciphers,
 * hashes and KDFs mis-handle far more often than random lengths do. */
static const size_t BOUNDARY_LEN[] = {
    0, 1, 15, 16, 17, 31, 32, 33, 55, 56, 63, 64, 65, 127, 128, 129, 255, 256
};
#define BOUNDARY_LEN_N (sizeof BOUNDARY_LEN / sizeof BOUNDARY_LEN[0])

/* Fold X25519's spec-permitted degenerate outputs to a single verdict: an
 * all-zero 32-byte shared secret becomes "ERR" (which is also what a library
 * that rejects low-order points emits), so a permitted error-vs-zero difference
 * is not reported as a divergence. Mutates hex in place. */
static void x25519_normalize(char *hex) {
    if (strlen(hex) != 2 * CMF_X25519_LEN) return;
    for (size_t j = 0; hex[j]; j++) if (hex[j] != '0') return;
    strcpy(hex, "ERR");
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <n> <seed> <name=path> [<name=path>...]\n", argv[0]);
        return 2;
    }
    long N = atol(argv[1]);
    g_state = strtoull(argv[2], NULL, 0);

    /* Build all request lines + cache the OpenSSL reference outputs. */
    char *reqpath = strdup("/tmp/cmf_diff_req_XXXXXX");
    int rfd = mkstemp(reqpath);
    if (rfd < 0) { perror("mkstemp"); return 2; }
    FILE *rf = fdopen(rfd, "w");

    char (*refhex)[8300] = malloc((size_t)N * sizeof *refhex);
    int *ops = malloc((size_t)N * sizeof *ops);
    if (!refhex || !ops) { fprintf(stderr, "oom\n"); return 2; }

    for (long i = 0; i < N; i++) {
        int op = (int)(rnd() % CMF_NUM_OPS);
        ops[i] = op;

        /* Verify-interop ops carry a packed (pub||sig||msg) payload in the msg
         * region and compare only the 1-byte accept/reject verdict. */
        if (op == 13 || op == 14) {
            uint8_t payload[2048]; size_t plen = 0; int verdict = 0;
            int gen = (op == 13) ? ecdsa_make_payload(payload, &plen, &verdict)
                                 : rsa_make_payload(payload, &plen, &verdict);
            if (gen != 0) {
                /* still emit a well-formed (empty-payload) request so the line
                 * count stays in lockstep; every backend will reply reject. */
                plen = 0; verdict = 0;
            }
            size_t need = CMF_KEYLEN + CMF_NONCELEN + 2 + plen;
            uint8_t *blob = malloc(need);
            memset(blob, 0, CMF_KEYLEN + CMF_NONCELEN + 2);   /* key/nonce/aadlen=0 */
            memcpy(blob + CMF_KEYLEN + CMF_NONCELEN + 2, payload, plen);
            fprintf(rf, "%d ", op);
            for (size_t j = 0; j < need; j++) fprintf(rf, "%c%c", HEX[blob[j]>>4], HEX[blob[j]&15]);
            fputc('\n', rf);
            strcpy(refhex[i], verdict ? "01" : "00");
            free(blob);
            continue;
        }

        size_t msglen = rnd() % 512;
        /* Boundary-length adversarial inputs (blind-spot B): occasionally pin the
         * message to a block/limb edge instead of a random length. */
        if (op != 12 && (rnd() % 4) == 0) msglen = BOUNDARY_LEN[rnd() % BOUNDARY_LEN_N];
        if (op == 12) msglen = CMF_X25519_LEN;   /* X25519 peer public key */
        size_t aadlen = (op == 3 || op == 4 || op == 9) ? (rnd() % 64) : 0;
        size_t need = CMF_KEYLEN + CMF_NONCELEN + 2 + aadlen + msglen;
        uint8_t *blob = malloc(need);
        rnd_bytes(blob, CMF_KEYLEN + CMF_NONCELEN);
        blob[CMF_KEYLEN + CMF_NONCELEN]     = (uint8_t)(aadlen >> 8);
        blob[CMF_KEYLEN + CMF_NONCELEN + 1] = (uint8_t)(aadlen & 0xFF);
        rnd_bytes(blob + CMF_KEYLEN + CMF_NONCELEN + 2, aadlen + msglen);
        /* X25519 adversarial peer keys (blind-spot B): on ~1/3 of vectors replace
         * the random peer u-coordinate with a known low-order / boundary point so
         * the degenerate scalar-mult paths are actually exercised. */
        if (op == 12 && (rnd() % 3) == 0)
            memcpy(blob + CMF_KEYLEN + CMF_NONCELEN + 2,
                   X25519_EDGE[rnd() % X25519_EDGE_N], CMF_X25519_LEN);
        /* X25519: clear bit 255 of the peer u-coordinate so it is in RFC 7748
         * canonical form. OpenSSL/BoringSSL/Botan mask this bit internally, but
         * wolfCrypt rejects a non-canonical peer key outright; masking here keeps
         * the differential well-defined over the actual scalar multiplication. */
        if (op == 12) blob[need - 1] &= 0x7F;

        /* request line: "<op> <hex-of-blob>\n" */
        fprintf(rf, "%d ", op);
        for (size_t j = 0; j < need; j++) fprintf(rf, "%c%c", HEX[blob[j]>>4], HEX[blob[j]&15]);
        fputc('\n', rf);

        /* parse the blob back into fields exactly as the CLI will, then ref-compute */
        cmf_vec_t v; memset(&v, 0, sizeof v);
        v.op = op;
        memcpy(v.key, blob, CMF_KEYLEN);
        memcpy(v.nonce, blob + CMF_KEYLEN, CMF_NONCELEN);
        v.aad = blob + CMF_KEYLEN + CMF_NONCELEN + 2; v.aadlen = aadlen;
        v.msg = v.aad + aadlen; v.msglen = msglen;
        uint8_t o[8192]; size_t on = 0;
        if (ref_compute(&v, o, &on) != 0) { strcpy(refhex[i], "ERR"); }
        else tohex(o, on, refhex[i]);
        if (op == 12) x25519_normalize(refhex[i]);   /* fold all-zero secret -> ERR */
        free(blob);
    }
    fclose(rf);

    /* ------------------------------------------------------------------ *
     * Collect every backend's full output, then run the oracle per vector.
     * Collecting first lets us MAJORITY-VOTE across all voters instead of
     * trusting OpenSSL by fiat (blind-spot C).
     * ------------------------------------------------------------------ */
    int nb = argc - 3;
    char (**bo)[8300] = malloc((size_t)nb * sizeof *bo);   /* bo[b][i] = reply hex */
    const char **bname = malloc((size_t)nb * sizeof *bname);
    long *bprod = calloc((size_t)nb, sizeof *bprod);       /* lines produced */
    long *bna   = calloc((size_t)nb, sizeof *bna);         /* "NA" replies */
    long *bdiv  = calloc((size_t)nb, sizeof *bdiv);        /* divergences */
    if (!bo || !bname || !bprod || !bna || !bdiv) { fprintf(stderr, "oom\n"); return 2; }

    for (int a = 3; a < argc; a++) {
        int b = a - 3;
        char *eq = strchr(argv[a], '=');
        if (!eq) { fprintf(stderr, "bad backend spec: %s\n", argv[a]); return 2; }
        *eq = '\0';
        bname[b] = argv[a];
        const char *path = eq + 1;
        bo[b] = malloc((size_t)N * sizeof *bo[b]);
        if (!bo[b]) { fprintf(stderr, "oom\n"); return 2; }
        for (long i = 0; i < N; i++) bo[b][i][0] = '\0';   /* '' = missing */

        /* Spawn the backend CLI via fork/exec instead of popen(): no shell is
         * involved, so a backend path containing quotes/spaces/metachars can
         * never break or be reinterpreted. Child reads the request file on
         * stdin and writes results on the pipe. */
        int fin = open(reqpath, O_RDONLY);
        if (fin < 0) { fprintf(stderr, "open req failed for %s\n", bname[b]); return 2; }
        int fd[2];
        if (pipe(fd) != 0) { fprintf(stderr, "pipe failed for %s\n", bname[b]); close(fin); return 2; }
        pid_t pid = fork();
        if (pid < 0) { fprintf(stderr, "fork failed for %s\n", bname[b]); close(fin); close(fd[0]); close(fd[1]); return 2; }
        if (pid == 0) {
            dup2(fin, STDIN_FILENO);
            dup2(fd[1], STDOUT_FILENO);
            close(fin); close(fd[0]); close(fd[1]);
            execl(path, path, (char *)NULL);
            _exit(127);
        }
        close(fin); close(fd[1]);
        FILE *p = fdopen(fd[0], "r");
        if (!p) { fprintf(stderr, "fdopen failed for %s\n", bname[b]); close(fd[0]); waitpid(pid, NULL, 0); return 2; }

        char *line = NULL; size_t cap = 0; long i = 0;
        while (i < N && getline(&line, &cap, p) > 0) {
            size_t ll = strlen(line);
            while (ll && (line[ll-1]=='\n' || line[ll-1]=='\r')) line[--ll] = '\0';
            if (strcmp(line, "NA") == 0) { strcpy(bo[b][i], "NA"); bna[b]++; i++; continue; }
            /* Apply the same X25519 degenerate-output normalisation to the
             * backend's reply as was applied to the reference. */
            if (ops[i] == 12) x25519_normalize(line);
            snprintf(bo[b][i], sizeof bo[b][i], "%s", line);
            i++;
        }
        fclose(p);
        waitpid(pid, NULL, 0);
        free(line);
        bprod[b] = i;
    }

    /* Per-vector oracle. Deterministic compute ops (0..12) use a MAJORITY VOTE
     * across all voters (OpenSSL reference + every backend that answered), so a
     * bug in ANY single implementation -- including OpenSSL itself -- surfaces
     * as the outlier instead of being trusted by fiat. Verify-interop ops
     * (13/14) stay reference-authoritative: OpenSSL is the signer that defined
     * the accept/reject ground truth. An "NA" reply abstains from the vote (NA
     * rates are exposed in the summary so a backend cannot silently opt out of
     * coverage and appear to "agree"). */
    int failures = 0;
    long ref_outlier = 0;
    for (long i = 0; i < N; i++) {
        const char *vv[16], *vn[16]; int vb[16], nv = 0;
        vv[nv] = refhex[i]; vn[nv] = "openssl"; vb[nv] = -1; nv++;
        for (int b = 0; b < nb && nv < 16; b++) {
            if (bprod[b] <= i) continue;                 /* short output: not a voter */
            if (strcmp(bo[b][i], "NA") == 0) continue;   /* abstains */
            vv[nv] = bo[b][i]; vn[nv] = bname[b]; vb[nv] = b; nv++;
        }
        if (nv <= 1) continue;   /* only the reference present: nothing to check */

        if (ops[i] == 13 || ops[i] == 14) {
            for (int j = 1; j < nv; j++)
                if (strcmp(vv[j], vv[0]) != 0) {
                    fprintf(stderr, "CMF_VIOLATION alg=DIFF-subproc oracle=VERIFY_mismatch detail=\"openssl(authority) vs %s disagree at vec #%ld op=%d\"\n", vn[j], i, ops[i]);
                    fprintf(stderr, "  openssl=%s  %s=%s\n", vv[0], vn[j], vv[j]);
                    bdiv[vb[j]]++; failures++;
                }
            continue;
        }

        if (nv == 2) {
            /* Only the reference + one backend: no third voter to form a
             * majority, so fall back to reference-authoritative pairwise. */
            if (strcmp(vv[1], vv[0]) != 0) {
                fprintf(stderr, "CMF_VIOLATION alg=DIFF-subproc oracle=DIFF_mismatch detail=\"openssl vs %s disagree at vec #%ld op=%d\"\n", vn[1], i, ops[i]);
                fprintf(stderr, "  openssl=%.48s  %s=%.48s\n", vv[0], vn[1], vv[1]);
                bdiv[vb[1]]++; failures++;
            }
            continue;
        }

        /* >= 3 voters: find the value backed by the most voters. */
        int bestcount = 0, bestj = 0;
        for (int j = 0; j < nv; j++) {
            int c = 0;
            for (int k = 0; k < nv; k++) if (strcmp(vv[j], vv[k]) == 0) c++;
            if (c > bestcount) { bestcount = c; bestj = j; }
        }
        if (bestcount == nv) continue;   /* unanimous agreement */
        if (bestcount * 2 <= nv) {
            /* no strict majority (e.g. a 2-2 split) -> unresolved divergence; no
             * ground truth exists, so it is not attributed to any one backend. */
            fprintf(stderr, "CMF_VIOLATION alg=DIFF-subproc oracle=DIFF_noconsensus detail=\"no majority among %d voters at vec #%ld op=%d\"\n", nv, i, ops[i]);
            for (int j = 0; j < nv; j++)
                fprintf(stderr, "  %s=%.48s\n", vn[j], vv[j]);
            failures++;
            continue;
        }
        const char *maj = vv[bestj];
        for (int j = 0; j < nv; j++) {
            if (strcmp(vv[j], maj) == 0) continue;
            fprintf(stderr, "CMF_VIOLATION alg=DIFF-subproc oracle=DIFF_mismatch detail=\"%s is minority vs majority at vec #%ld op=%d\"\n", vn[j], i, ops[i]);
            fprintf(stderr, "  majority=%.48s  %s=%.48s\n", maj, vn[j], vv[j]);
            if (vb[j] >= 0) bdiv[vb[j]]++; else ref_outlier++;
            failures++;
        }
    }

    /* NA exposure + per-backend summary: silent non-implementation is now
     * visible, and a backend that abstained on everything is called out. */
    for (int b = 0; b < nb; b++) {
        fprintf(stderr, "[diff-subproc] %s: answered %ld/%ld, NA %ld, diverged %ld\n",
                bname[b], bprod[b], N, bna[b], bdiv[b]);
        if (bprod[b] < N)
            fprintf(stderr, "[diff-subproc] WARNING: %s produced only %ld/%ld outputs\n", bname[b], bprod[b], N);
        if (bna[b] == N)
            fprintf(stderr, "[diff-subproc] WARNING: %s replied NA to all %ld vectors (no differential coverage)\n", bname[b], N);
    }
    if (ref_outlier)
        fprintf(stderr, "[diff-subproc] NOTE: openssl was outvoted on %ld vector(s) -- the reference may be the buggy implementation\n", ref_outlier);

    remove(reqpath);
    free(reqpath);
    free(refhex);
    free(ops);
    for (int b = 0; b < nb; b++) free(bo[b]);
    free(bo); free(bname); free(bprod); free(bna); free(bdiv);
    if (failures) { fprintf(stderr, "[diff-subproc] %d backend(s) diverged\n", failures); return 1; }
    fprintf(stderr, "[diff-subproc] all backends agree\n");
    return 0;
}
