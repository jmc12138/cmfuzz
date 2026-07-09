/*
 * CMFuzz stage 2.5a — FHE cross-library differential (OpenFHE vs Microsoft SEAL).
 *
 * Earlier the FHE pillar only had metamorphic oracles on a single library
 * (SEAL BFV: homomorphic correctness + distributivity). This adds the missing
 * O1 cross-implementation differential between two independent FHE libraries.
 *
 * FHE ciphertexts are library-specific (different RNS layouts, key formats) and
 * encryption is randomised, so — exactly like the PQC and public-key
 * verify-interop differentials — we do NOT compare ciphertext bytes. Instead we
 * compare the *decrypted plaintext results* of the same BFV computation run
 * independently in each library, under the same plaintext modulus t:
 *
 *   for random a,b,c in [0,t):
 *     add   : Dec(Enc(a)+Enc(b))            must equal (a+b) mod t in BOTH libs
 *     mul   : Dec(Enc(a)*Enc(b))            must equal (a*b) mod t in BOTH libs
 *     distr : Dec(Enc(a)*(Enc(b)+Enc(c)))   must equal a*(b+c) mod t in BOTH libs
 *   and the two libraries must agree with each other.
 *
 * Divergence (a genuine cross-library FHE arithmetic disagreement) fires
 * O1_fhe_bfv_interop. CMF_FHE_FAULT=1 corrupts one SEAL result so the negative
 * self-test proves the differential catches a divergent backend.
 */
#include "seal/seal.h"
#include "openfhe.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

extern "C" {
#include "../engine/cmfuzz_common.h"
}

static const uint64_t T = 65537; /* prime, 2^16+1: supports batching in both libs */
#define ALG "FHE-BFV"

/* ---- SEAL BFV backend --------------------------------------------------- */
struct SealBfv {
    seal::SEALContext ctx;
    seal::SecretKey sk;
    seal::PublicKey pk;
    seal::RelinKeys relin;
    seal::BatchEncoder encoder;
    seal::Encryptor encryptor;
    seal::Evaluator eval;
    seal::Decryptor decryptor;
    size_t slots;

    static seal::EncryptionParameters make_parms() {
        seal::EncryptionParameters parms(seal::scheme_type::bfv);
        parms.set_poly_modulus_degree(8192);
        parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(8192));
        parms.set_plain_modulus(T);
        return parms;
    }

    /* two-phase init: build the keys first, then hand them to the members */
    static SealBfv *create() {
        auto parms = make_parms();
        seal::SEALContext c(parms);
        seal::KeyGenerator kg(c);
        seal::SecretKey s = kg.secret_key();
        seal::PublicKey p; kg.create_public_key(p);
        seal::RelinKeys r; kg.create_relin_keys(r);
        return new SealBfv(std::move(c), std::move(s), std::move(p), std::move(r));
    }
    SealBfv(seal::SEALContext c, seal::SecretKey s, seal::PublicKey p, seal::RelinKeys r)
        : ctx(std::move(c)), sk(std::move(s)), pk(std::move(p)), relin(std::move(r)),
          encoder(ctx), encryptor(ctx, pk), eval(ctx), decryptor(ctx, sk),
          slots(encoder.slot_count()) {}

    seal::Ciphertext enc(uint64_t x) {
        std::vector<uint64_t> v(slots, 0); v[0] = x % T;
        seal::Plaintext pt; encoder.encode(v, pt);
        seal::Ciphertext ct; encryptor.encrypt(pt, ct); return ct;
    }
    uint64_t dec(const seal::Ciphertext &ct) {
        seal::Plaintext pt; decryptor.decrypt(ct, pt);
        std::vector<uint64_t> v; encoder.decode(pt, v); return v[0] % T;
    }
    uint64_t add(uint64_t a, uint64_t b) {
        auto ca = enc(a), cb = enc(b);
        seal::Ciphertext s; eval.add(ca, cb, s); return dec(s);
    }
    uint64_t mul(uint64_t a, uint64_t b) {
        auto ca = enc(a), cb = enc(b);
        seal::Ciphertext p; eval.multiply(ca, cb, p); eval.relinearize_inplace(p, relin);
        return dec(p);
    }
    uint64_t distr(uint64_t a, uint64_t b, uint64_t c) {
        auto ca = enc(a), cb = enc(b), cc = enc(c);
        seal::Ciphertext bc; eval.add(cb, cc, bc);
        seal::Ciphertext lhs; eval.multiply(ca, bc, lhs); eval.relinearize_inplace(lhs, relin);
        return dec(lhs);
    }
};

/* ---- OpenFHE BFV backend ------------------------------------------------ */
using namespace lbcrypto;
struct OfheBfv {
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> kp;

    OfheBfv() {
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(T);
        parameters.SetMultiplicativeDepth(2);
        cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        kp = cc->KeyGen();
        cc->EvalMultKeyGen(kp.secretKey);
    }
    Ciphertext<DCRTPoly> enc(uint64_t x) {
        Plaintext p = cc->MakePackedPlaintext({(int64_t)(x % T)});
        return cc->Encrypt(kp.publicKey, p);
    }
    uint64_t dec(const Ciphertext<DCRTPoly> &ct) {
        Plaintext r; cc->Decrypt(kp.secretKey, ct, &r);
        r->SetLength(1);
        int64_t v = r->GetPackedValue()[0];
        v %= (int64_t)T; if (v < 0) v += (int64_t)T;
        return (uint64_t)v;
    }
    uint64_t add(uint64_t a, uint64_t b) { return dec(cc->EvalAdd(enc(a), enc(b))); }
    uint64_t mul(uint64_t a, uint64_t b) { return dec(cc->EvalMult(enc(a), enc(b))); }
    uint64_t distr(uint64_t a, uint64_t b, uint64_t c) {
        auto ca = enc(a), cb = enc(b), cc2 = enc(c);
        return dec(cc->EvalMult(ca, cc->EvalAdd(cb, cc2)));
    }
};

int main(int argc, char **argv) {
    long iters = (argc > 1) ? atol(argv[1]) : 200;
    unsigned seed = (argc > 2) ? (unsigned)atol(argv[2]) : 42;
    srand(seed);

    SealBfv *S = SealBfv::create();
    OfheBfv *O = new OfheBfv();

    for (long i = 0; i < iters; i++) {
        uint64_t a = (uint64_t)rand() % T;
        uint64_t b = (uint64_t)rand() % T;
        uint64_t c = (uint64_t)rand() % T;

        uint64_t p_add = (a + b) % T;
        uint64_t p_mul = (a * b) % T;
        uint64_t p_dis = (a * ((b + c) % T)) % T;

        uint64_t s_add = S->add(a, b);
        uint64_t s_mul = S->mul(a, b);
        uint64_t s_dis = S->distr(a, b, c);
#ifdef CMF_FHE_FAULT
        s_add ^= 1; /* corrupt one SEAL result to prove the differential fires */
#endif
        uint64_t o_add = O->add(a, b);
        uint64_t o_mul = O->mul(a, b);
        uint64_t o_dis = O->distr(a, b, c);

        /* each library must be correct, and the two must agree */
        if (s_add != p_add || o_add != p_add || s_add != o_add)
            CMF_VIOLATION(ALG, "O1_fhe_bfv_interop", "SEAL vs OpenFHE homomorphic add disagree");
        if (s_mul != p_mul || o_mul != p_mul || s_mul != o_mul)
            CMF_VIOLATION(ALG, "O1_fhe_bfv_interop", "SEAL vs OpenFHE homomorphic mul disagree");
        if (s_dis != p_dis || o_dis != p_dis || s_dis != o_dis)
            CMF_VIOLATION(ALG, "O1_fhe_bfv_interop", "SEAL vs OpenFHE distributivity disagree");
    }
    printf("[fhe-diff] BFV OpenFHE<->SEAL: %ld iters, add/mul/distributivity agree (t=%llu)\n",
           iters, (unsigned long long)T);
    delete S; delete O;
    return 0;
}
