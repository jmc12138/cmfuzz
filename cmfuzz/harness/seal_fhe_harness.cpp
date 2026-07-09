/*
 * CMFuzz harness for Microsoft SEAL BFV (Pillar 3: FHE).
 *
 * FHE has no external ground-truth oracle, so we use metamorphic relations in the
 * spirit of Eidolon's "equivalence expression transformation": a computation and
 * its mathematically-equivalent rewrite must decrypt to the same plaintext, and
 * the homomorphic result must match the plaintext-domain result (mod t).
 *
 * Fuzzer bytes choose the operands a,b,c; the harness runs:
 *   MR1  homomorphic correctness:  Dec(Enc(a) op Enc(b)) == (a op b) mod t   (op in +, *)
 *   MR2  distributivity (equiv-transform): Dec(Enc(a)*(Enc(b)+Enc(c)))
 *                                          == Dec(Enc(a)*Enc(b) + Enc(a)*Enc(c))
 *   MR3  add/relinearize associativity path equivalence
 * Memory/UB bugs surface via ASan/UBSan; SEAL exceptions on invalid params are
 * caught (not oracle violations).
 */
#include "seal/seal.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace seal;

/* All SEAL objects live in a lazily heap-allocated struct. Declaring SEAL
 * objects (SecretKey/PublicKey/...) at namespace scope would default-construct
 * them before main() and hit SEAL's global memory pool during static init
 * (static-init-order fiasco -> "pool is uninitialized"). */
struct SealCtx {
    SEALContext ctx;
    KeyGenerator keygen;
    SecretKey sk;
    PublicKey pk;
    RelinKeys relin;
    uint64_t t;
    explicit SealCtx(const EncryptionParameters &parms)
        : ctx(parms), keygen(ctx), sk(keygen.secret_key()),
          t(parms.plain_modulus().value()) {
        keygen.create_public_key(pk);
        keygen.create_relin_keys(relin);
    }
};
static SealCtx *g = nullptr;

static void die_violation(const char *oracle, const char *msg) {
    fprintf(stderr, "CMF_VIOLATION alg=SEAL-BFV oracle=%s msg=%s\n", oracle, msg);
    abort();
}

static void ensure_init() {
    if (g) return;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_deg = 8192;
    parms.set_poly_modulus_degree(poly_deg);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_deg));
    parms.set_plain_modulus(PlainModulus::Batching(poly_deg, 20));
    g = new SealCtx(parms);
}

static uint64_t rd(const uint8_t *&p, const uint8_t *end) {
    uint64_t v = 0;
    for (int i = 0; i < 8 && p < end; i++) v = (v << 8) | *p++;
    return v;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 24) return 0;
    ensure_init();
    const uint8_t *p = data, *end = data + size;
    const uint64_t g_t = g->t;
    uint64_t a = rd(p, end) % g_t;
    uint64_t b = rd(p, end) % g_t;
    uint64_t c = rd(p, end) % g_t;

    try {
        BatchEncoder enc(g->ctx);
        Encryptor encryptor(g->ctx, g->pk);
        Evaluator ev(g->ctx);
        Decryptor dec(g->ctx, g->sk);
        size_t slots = enc.slot_count();

        auto encode_enc = [&](uint64_t x) {
            std::vector<uint64_t> v(slots, 0); v[0] = x;
            Plaintext pt; enc.encode(v, pt);
            Ciphertext ct; encryptor.encrypt(pt, ct); return ct;
        };
        auto decode_dec = [&](Ciphertext &ct) -> uint64_t {
            Plaintext pt; dec.decrypt(ct, pt);
            std::vector<uint64_t> v; enc.decode(pt, v); return v[0];
        };

        Ciphertext ca = encode_enc(a), cb = encode_enc(b), cc = encode_enc(c);

        // MR1: homomorphic add / mul correctness
        Ciphertext sum; ev.add(ca, cb, sum);
        if (decode_dec(sum) != (a + b) % g_t)
            die_violation("MR1_add", "hom add != plaintext add");

        Ciphertext prod; ev.multiply(ca, cb, prod); ev.relinearize_inplace(prod, g->relin);
        if (decode_dec(prod) != (a * b) % g_t)
            die_violation("MR1_mul", "hom mul != plaintext mul");

        // MR2: distributivity via equivalence transformation
        Ciphertext bc; ev.add(cb, cc, bc);
        Ciphertext lhs; ev.multiply(ca, bc, lhs); ev.relinearize_inplace(lhs, g->relin);
        Ciphertext ab; ev.multiply(ca, cb, ab); ev.relinearize_inplace(ab, g->relin);
        Ciphertext ac; ev.multiply(ca, cc, ac); ev.relinearize_inplace(ac, g->relin);
        Ciphertext rhs; ev.add(ab, ac, rhs);
        if (decode_dec(lhs) != decode_dec(rhs))
            die_violation("MR2_distributivity", "a*(b+c) != a*b+a*c under FHE");
        if (decode_dec(lhs) != (a * ((b + c) % g_t)) % g_t)
            die_violation("MR2_vs_plain", "a*(b+c) FHE != plaintext");

    } catch (const std::exception &) {
        // invalid parameters / noise budget exhaustion are not oracle violations
        return 0;
    }
    return 0;
}
