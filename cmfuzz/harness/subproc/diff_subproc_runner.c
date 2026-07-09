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
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
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
    }
    return -1;
}

#define CMF_NUM_OPS 11   /* ops 0..10 (see compute_common.h) */

static const char *HEX = "0123456789abcdef";
static void tohex(const uint8_t *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) { out[2*i] = HEX[b[i]>>4]; out[2*i+1] = HEX[b[i]&15]; }
    out[2*n] = '\0';
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
    if (!refhex) { fprintf(stderr, "oom\n"); return 2; }

    for (long i = 0; i < N; i++) {
        int op = (int)(rnd() % CMF_NUM_OPS);
        size_t msglen = rnd() % 512;
        size_t aadlen = (op == 3 || op == 4 || op == 9) ? (rnd() % 64) : 0;
        size_t need = CMF_KEYLEN + CMF_NONCELEN + 2 + aadlen + msglen;
        uint8_t *blob = malloc(need);
        rnd_bytes(blob, CMF_KEYLEN + CMF_NONCELEN);
        blob[CMF_KEYLEN + CMF_NONCELEN]     = (uint8_t)(aadlen >> 8);
        blob[CMF_KEYLEN + CMF_NONCELEN + 1] = (uint8_t)(aadlen & 0xFF);
        rnd_bytes(blob + CMF_KEYLEN + CMF_NONCELEN + 2, aadlen + msglen);

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
        free(blob);
    }
    fclose(rf);

    int failures = 0;
    for (int a = 3; a < argc; a++) {
        char *eq = strchr(argv[a], '=');
        if (!eq) { fprintf(stderr, "bad backend spec: %s\n", argv[a]); return 2; }
        *eq = '\0';
        const char *name = argv[a], *path = eq + 1;

        char cmd[1024];
        snprintf(cmd, sizeof cmd, "'%s' < '%s'", path, reqpath);
        FILE *p = popen(cmd, "r");
        if (!p) { fprintf(stderr, "popen failed for %s\n", name); return 2; }

        char *line = NULL; size_t cap = 0; long i = 0; int mism = 0;
        while (i < N && getline(&line, &cap, p) > 0) {
            size_t ll = strlen(line);
            while (ll && (line[ll-1]=='\n' || line[ll-1]=='\r')) line[--ll] = '\0';
            /* "NA" = backend does not implement this op -> skip (not a bug). */
            if (strcmp(line, "NA") == 0) { i++; continue; }
            if (strcmp(line, refhex[i]) != 0) {
                char msg[160];
                snprintf(msg, sizeof msg, "openssl vs %s disagree at vec #%ld (op-seeded)", name, i);
                fprintf(stderr, "CMF_VIOLATION alg=DIFF-subproc oracle=DIFF_mismatch detail=\"%s\"\n", msg);
                fprintf(stderr, "  openssl=%.64s...\n  %s=%.64s...\n", refhex[i], name, line);
                mism = 1; failures++;
                break;
            }
            i++;
        }
        pclose(p);
        free(line);
        if (!mism && i < N)
            { fprintf(stderr, "backend %s produced only %ld/%ld outputs\n", name, i, N); failures++; }
        else if (!mism)
            fprintf(stderr, "[diff-subproc] %s agrees on %ld vectors\n", name, N);
    }

    remove(reqpath);
    free(reqpath);
    free(refhex);
    if (failures) { fprintf(stderr, "[diff-subproc] %d backend(s) diverged\n", failures); return 1; }
    fprintf(stderr, "[diff-subproc] all backends agree\n");
    return 0;
}
