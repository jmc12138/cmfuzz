/*
 * CMFuzz subprocess differential CLI — Botan backend (stage 2.1).
 *
 * Standalone binary linking ONLY Botan (C++). Botan lives in its own Botan::
 * namespace and models symmetric crypto with HashFunction / MessageAuthentication
 * Code / AEAD_Mode objects — a state machine distinct from OpenSSL's EVP, so
 * keeping it behind a subprocess yields a uniform, byte-exact differential.
 * Reads request lines on stdin, prints one hex output line per request; see
 * compute_common.h for the wire protocol.
 *
 * CMF_DIFF_FAULT=1 flips the first output byte, so the differential runner's
 * negative self-test can prove it actually catches a divergent implementation.
 */
#include "botan_all.h"    /* Botan amalgamation (built by scripts/build_botan.sh) */
#include <vector>
#include <memory>
#include "compute_common.h"

static int digest(const char *name, const cmf_vec_t *v, uint8_t *out, size_t *n) {
    auto h = Botan::HashFunction::create(name);
    if (!h) return -1;
    h->update(v->msg, v->msglen);
    auto d = h->final();
    memcpy(out, d.data(), d.size());
    *n = d.size();
    return 0;
}

static int hmac256(const cmf_vec_t *v, uint8_t *out, size_t *n) {
    auto m = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
    if (!m) return -1;
    m->set_key(v->key, CMF_KEYLEN);
    m->update(v->msg, v->msglen);
    auto t = m->final();
    memcpy(out, t.data(), t.size());
    *n = t.size();
    return 0;
}

static int aead(const char *name, const cmf_vec_t *v, uint8_t *out, size_t *n) {
    auto enc = Botan::AEAD_Mode::create(name, Botan::Cipher_Dir::Encryption);
    if (!enc) return -1;
    enc->set_key(v->key, CMF_KEYLEN);
    enc->set_associated_data(v->aad, v->aadlen);
    enc->start(v->nonce, CMF_NONCELEN);
    Botan::secure_vector<uint8_t> buf(v->msg, v->msg + v->msglen);
    enc->finish(buf);                 /* buf = ciphertext || tag */
    memcpy(out, buf.data(), buf.size());
    *n = buf.size();
    return 0;
}

int main(void) {
    char *line = NULL; size_t cap = 0; ssize_t len;
    uint8_t out[4096 + 64];
    while ((len = getline(&line, &cap, stdin)) > 0) {
        cmf_vec_t v; size_t n = 0; int rc = -1;
        if (cmf_vec_parse(line, &v) == 0) {
            try {
                switch (v.op) {
                    case 0: rc = digest("SHA-256", &v, out, &n); break;
                    case 1: rc = digest("SHA-512", &v, out, &n); break;
                    case 2: rc = hmac256(&v, out, &n); break;
                    case 3: rc = aead("ChaCha20Poly1305", &v, out, &n); break;
                    case 4: rc = aead("AES-256/GCM", &v, out, &n); break;
                }
            } catch (...) { rc = -1; }
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
