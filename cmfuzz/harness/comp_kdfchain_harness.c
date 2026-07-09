/*
 * CMFuzz L2 (composition) harness — KDF chain / key-schedule ratchet.
 *
 * A chain of per-message keys derived from initial keying material the way a
 * ratchet / key schedule does:  k_0 = HKDF(ikm, "chain"),  k_{i+1} = HKDF(k_i).
 * Each message i is AEAD-sealed (AES-256-GCM) under its own k_i.
 *
 * Composition oracles (O5):
 *   O5-roundtrip       : open message i under k_i -> plaintext i.
 *   O5-key-separation  : opening message i's ciphertext under k_j (j != i) MUST fail.
 *                        The chain's whole purpose is that each step yields an
 *                        independent key; if steps collapse, one message's key
 *                        decrypts another's — exactly the ratchet bug this catches.
 *
 * Fault CMF_FAULT_KDF=1 : the chain does not advance (k_{i+1} = k_i), so all keys
 *                         are equal and cross-decryption succeeds -> O5-key-separation
 *                         fires.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include "../engine/cmfuzz_common.h"

#define N_CHAIN 4

static int hkdf32(const uint8_t *key, size_t klen, const char *info, uint8_t out[32]) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[4], *p = params;
    char digest[] = "SHA256";
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, klen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, strlen(info));
    *p = OSSL_PARAM_construct_end();
    int ok = EVP_KDF_derive(kctx, out, 32, params) > 0;
    EVP_KDF_CTX_free(kctx); EVP_KDF_free(kdf);
    return ok;
}
static int gcm_seal(const uint8_t k[32], const uint8_t *m, int n, uint8_t *out) {
    uint8_t nonce[12] = {0};
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, ctn = 0;
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, k, nonce);
    EVP_EncryptUpdate(c, out, &l, m, n); ctn = l;
    EVP_EncryptFinal_ex(c, out + ctn, &l); ctn += l;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, out + ctn);
    EVP_CIPHER_CTX_free(c); return ctn + 16;
}
static int gcm_open(const uint8_t k[32], const uint8_t *ct, int ctn, uint8_t *out) {
    uint8_t nonce[12] = {0};
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, ok;
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, k, nonce);
    EVP_DecryptUpdate(c, out, &l, ct, ctn - 16);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(ct + ctn - 16));
    ok = EVP_DecryptFinal_ex(c, out + l, &l);
    EVP_CIPHER_CTX_free(c); return ok == 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    cmf_prng_seed(data, size);
    cmf_reader_t r; cmf_reader_init(&r, data, size);

    uint8_t ikm[32]; cmf_randombytes(ikm, 32);
    uint8_t keys[N_CHAIN][32];
    hkdf32(ikm, 32, "chain", keys[0]);
    for (int i = 1; i < N_CHAIN; i++) {
#ifdef CMF_FAULT_KDF
        memcpy(keys[i], keys[i - 1], 32);      /* fault: chain does not advance */
#else
        hkdf32(keys[i - 1], 32, "chain", keys[i]);
#endif
    }

    uint8_t msg[N_CHAIN][16], ct[N_CHAIN][16 + 16], pt[32];
    int ctn[N_CHAIN];
    for (int i = 0; i < N_CHAIN; i++) {
        cmf_randombytes(msg[i], 16);
        msg[i][0] = (uint8_t)i;                 /* make messages distinct */
        ctn[i] = gcm_seal(keys[i], msg[i], 16, ct[i]);
    }

    /* O5-roundtrip: each message opens under its own key */
    for (int i = 0; i < N_CHAIN; i++) {
        int ok = gcm_open(keys[i], ct[i], ctn[i], pt);
        CMF_ASSERT(ok && memcmp(pt, msg[i], 16) == 0, "KDF-chain(HKDF+AES-GCM)",
                   "O5-roundtrip", "message did not open under its own chain key");
    }

    /* O5-key-separation: message i must NOT open under key j (j != i) */
    uint8_t i = cmf_u8(&r) % N_CHAIN, j = cmf_u8(&r) % N_CHAIN;
    if (i != j) {
        int ok = gcm_open(keys[j], ct[i], ctn[i], pt);
        CMF_ASSERT(!ok, "KDF-chain(HKDF+AES-GCM)", "O5-key-separation",
                   "a chain key decrypted another step's message");
    }
    return 0;
}
