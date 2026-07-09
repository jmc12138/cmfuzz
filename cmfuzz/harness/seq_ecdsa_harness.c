/*
 * CMFuzz L3 (sequence / API-misuse) harness — ECDSA per-signature nonce contract (O6).
 *
 * ECDSA's security depends on a UNIQUE, secret per-signature nonce k. Reusing k
 * across two distinct messages (the classic Sony PS3 / Android SecureRandom bug)
 * leaks the long-term private key. We drive a raw ECDSA signer (P-256) whose
 * nonce comes from a "nonce source" and check the sequence-level contract:
 *
 *   O6-ecdsa-k-uniqueness : two signatures over distinct messages must have
 *       distinct r components (r = x(k*G)); equal r == a reused nonce.
 *
 * When k is reused we surface the concrete consequence — full private-key
 * recovery from (r, s1, s2, z1, z2):
 *       k = (z1 - z2) / (s1 - s2),   d = (s1*k - z1) / r   (mod n)
 *
 * Fault:
 *   CMF_FAULT_KREUSE=1 : nonce source returns a constant -> O6-ecdsa-k-uniqueness fires.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include "../engine/cmfuzz_common.h"

#define ALG "ECDSA-P256/seq"

/* Per-signature nonce source. Correct: fresh random each call. Fault: constant. */
static void nonce_k(const BIGNUM *order, BN_CTX *ctx, BIGNUM *k) {
#ifdef CMF_FAULT_KREUSE
    BN_set_word(k, 0x0123456789abcdefULL);   /* fault: fixed nonce */
    BN_mod(k, k, order, ctx);
#else
    (void)ctx;
    BN_rand_range(k, order);                  /* correct: fresh per-signature nonce */
#endif
    if (BN_is_zero(k)) BN_set_word(k, 1);
}

/* Raw ECDSA sign with caller-controlled k. Returns 1 on success. */
static int ecdsa_sign(const EC_GROUP *g, const BIGNUM *order, const BIGNUM *d,
                      const uint8_t *msg, size_t mlen, BN_CTX *ctx,
                      BIGNUM *r, BIGNUM *s) {
    uint8_t h[32]; SHA256(msg, mlen, h);
    BIGNUM *z = BN_CTX_get(ctx), *k = BN_CTX_get(ctx), *kinv = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    EC_POINT *R = EC_POINT_new(g);
    BN_bin2bn(h, 32, z); BN_mod(z, z, order, ctx);
    nonce_k(order, ctx, k);
    if (!EC_POINT_mul(g, R, k, NULL, NULL, ctx)) { EC_POINT_free(R); return 0; }
    EC_POINT_get_affine_coordinates(g, R, r, NULL, ctx);
    BN_mod(r, r, order, ctx);
    if (BN_is_zero(r)) { EC_POINT_free(R); return 0; }
    /* s = k^{-1} (z + r*d) mod n */
    BN_mod_inverse(kinv, k, order, ctx);
    BN_mod_mul(tmp, r, d, order, ctx);
    BN_mod_add(tmp, tmp, z, order, ctx);
    BN_mod_mul(s, kinv, tmp, order, ctx);
    EC_POINT_free(R);
    return !BN_is_zero(s);
}

static int ecdsa_verify(const EC_GROUP *g, const BIGNUM *order, const EC_POINT *pub,
                        const uint8_t *msg, size_t mlen, BN_CTX *ctx,
                        const BIGNUM *r, const BIGNUM *s) {
    uint8_t h[32]; SHA256(msg, mlen, h);
    BIGNUM *z = BN_CTX_get(ctx), *w = BN_CTX_get(ctx);
    BIGNUM *u1 = BN_CTX_get(ctx), *u2 = BN_CTX_get(ctx), *x = BN_CTX_get(ctx);
    EC_POINT *P = EC_POINT_new(g);
    BN_bin2bn(h, 32, z); BN_mod(z, z, order, ctx);
    BN_mod_inverse(w, s, order, ctx);
    BN_mod_mul(u1, z, w, order, ctx);
    BN_mod_mul(u2, r, w, order, ctx);
    EC_POINT_mul(g, P, u1, pub, u2, ctx);      /* u1*G + u2*pub */
    EC_POINT_get_affine_coordinates(g, P, x, NULL, ctx);
    BN_mod(x, x, order, ctx);
    int ok = BN_cmp(x, r) == 0;
    EC_POINT_free(P);
    return ok;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    cmf_prng_seed(data, size);

    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *ctx = BN_CTX_new(); BN_CTX_start(ctx);
    const BIGNUM *order = EC_GROUP_get0_order(g);
    BIGNUM *d = BN_CTX_get(ctx);
    BN_rand_range(d, order); if (BN_is_zero(d)) BN_set_word(d, 1);
    EC_POINT *pub = EC_POINT_new(g);
    EC_POINT_mul(g, pub, d, NULL, NULL, ctx);

    /* two DISTINCT messages derived from the fuzz input */
    uint8_t m1[16], m2[16];
    cmf_randombytes(m1, 16); cmf_randombytes(m2, 16);
    m1[0] = 0xA1; m2[0] = 0xB2;

    BIGNUM *r1 = BN_CTX_get(ctx), *s1 = BN_CTX_get(ctx);
    BIGNUM *r2 = BN_CTX_get(ctx), *s2 = BN_CTX_get(ctx);
    if (ecdsa_sign(g, order, d, m1, 16, ctx, r1, s1) &&
        ecdsa_sign(g, order, d, m2, 16, ctx, r2, s2)) {
        /* honest signatures must verify (sanity) */
        CMF_ASSERT(ecdsa_verify(g, order, pub, m1, 16, ctx, r1, s1), ALG,
                   "O6-sign-verify", "honest ECDSA signature failed to verify");

        int kreused = BN_cmp(r1, r2) == 0;      /* equal r <=> reused nonce */
        CMF_ASSERT(!kreused, ALG, "O6-ecdsa-k-uniqueness",
                   "per-signature nonce reused across distinct messages");
        if (kreused) {
            /* concrete consequence: recover the private key */
            uint8_t h1[32], h2[32]; SHA256(m1, 16, h1); SHA256(m2, 16, h2);
            BIGNUM *z1 = BN_CTX_get(ctx), *z2 = BN_CTX_get(ctx);
            BIGNUM *k = BN_CTX_get(ctx), *dr = BN_CTX_get(ctx), *t = BN_CTX_get(ctx);
            BN_bin2bn(h1, 32, z1); BN_mod(z1, z1, order, ctx);
            BN_bin2bn(h2, 32, z2); BN_mod(z2, z2, order, ctx);
            BN_mod_sub(t, s1, s2, order, ctx);   /* s1 - s2 */
            BN_mod_inverse(t, t, order, ctx);
            BN_mod_sub(k, z1, z2, order, ctx);   /* z1 - z2 */
            BN_mod_mul(k, k, t, order, ctx);     /* k = (z1-z2)/(s1-s2) */
            BN_mod_mul(dr, s1, k, order, ctx);   /* s1*k */
            BN_mod_sub(dr, dr, z1, order, ctx);  /* s1*k - z1 */
            BN_mod_inverse(t, r1, order, ctx);
            BN_mod_mul(dr, dr, t, order, ctx);   /* d = (s1*k - z1)/r */
            CMF_ASSERT(BN_cmp(dr, d) != 0, ALG, "O6-ecdsa-k-uniqueness",
                       "nonce reuse allowed full private-key recovery");
        }
    }
    EC_POINT_free(pub);
    BN_CTX_end(ctx); BN_CTX_free(ctx); EC_GROUP_free(g);
    return 0;
}
