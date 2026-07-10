/*
 * CMFuzz stage 2.5c — CKKS cross-library differential (OpenFHE vs Microsoft SEAL).
 *
 * The FHE pillar previously had a CKKS oracle on a single library only (SEAL,
 * fhe_ckks: an approximate-arithmetic error-bound check). This adds the missing
 * O1 cross-implementation differential for CKKS between two independent
 * libraries, mirroring the existing BFV differential (fhe_diff).
 *
 * CKKS is *approximate*: there is no exact plaintext to match, and ciphertext
 * layouts/scales differ per library, so we compare decrypted real results.
 * For random reals a,b:
 *
 *   add : SEAL and OpenFHE must each be within an absolute error bound of a+b,
 *         AND agree with each other within a cross-library tolerance.
 *   mul : same, against a*b, with a looser (relative) bound.
 *
 * Both libraries being close to the true value but far from *each other* would
 * still fire — that is exactly the cross-library disagreement O1 is meant to
 * catch. Firing oracle: O1_ckks_interop.
 *
 * CMF_FHE_FAULT=1 perturbs one SEAL result far beyond the bound so the negative
 * self-test proves the differential catches a divergent backend.
 */
#include "seal/seal.h"
#include "openfhe.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

extern "C" {
#include "../engine/cmfuzz_common.h"
}

#define ALG "FHE-CKKS"

/* ---- SEAL CKKS backend -------------------------------------------------- */
struct SealCkks {
    seal::SEALContext ctx;
    seal::SecretKey sk;
    seal::PublicKey pk;
    seal::RelinKeys relin;
    seal::CKKSEncoder encoder;
    seal::Encryptor encryptor;
    seal::Evaluator eval;
    seal::Decryptor decryptor;
    double scale;

    static seal::EncryptionParameters make_parms() {
        seal::EncryptionParameters parms(seal::scheme_type::ckks);
        parms.set_poly_modulus_degree(8192);
        parms.set_coeff_modulus(seal::CoeffModulus::Create(8192, {60, 40, 40, 60}));
        return parms;
    }
    static SealCkks *create() {
        auto parms = make_parms();
        seal::SEALContext c(parms);
        seal::KeyGenerator kg(c);
        seal::SecretKey s = kg.secret_key();
        seal::PublicKey p; kg.create_public_key(p);
        seal::RelinKeys r; kg.create_relin_keys(r);
        return new SealCkks(std::move(c), std::move(s), std::move(p), std::move(r));
    }
    SealCkks(seal::SEALContext c, seal::SecretKey s, seal::PublicKey p, seal::RelinKeys r)
        : ctx(std::move(c)), sk(std::move(s)), pk(std::move(p)), relin(std::move(r)),
          encoder(ctx), encryptor(ctx, pk), eval(ctx), decryptor(ctx, sk),
          scale(std::pow(2.0, 40)) {}

    seal::Ciphertext enc(double x) {
        seal::Plaintext pt; encoder.encode(x, scale, pt);
        seal::Ciphertext ct; encryptor.encrypt(pt, ct); return ct;
    }
    double dec(const seal::Ciphertext &ct) {
        seal::Plaintext pt; decryptor.decrypt(ct, pt);
        std::vector<double> v; encoder.decode(pt, v); return v[0];
    }
    double add(double a, double b) {
        auto ca = enc(a), cb = enc(b);
        seal::Ciphertext s; eval.add(ca, cb, s); return dec(s);
    }
    double mul(double a, double b) {
        auto ca = enc(a), cb = enc(b);
        seal::Ciphertext p; eval.multiply(ca, cb, p);
        eval.relinearize_inplace(p, relin);
        eval.rescale_to_next_inplace(p);
        return dec(p);
    }
};

/* ---- OpenFHE CKKS backend ----------------------------------------------- */
using namespace lbcrypto;
struct OfheCkks {
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> kp;

    OfheCkks() {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(2);
        parameters.SetScalingModSize(40);
        parameters.SetBatchSize(8);
        cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        kp = cc->KeyGen();
        cc->EvalMultKeyGen(kp.secretKey);
    }
    Ciphertext<DCRTPoly> enc(double x) {
        Plaintext p = cc->MakeCKKSPackedPlaintext(std::vector<double>{x});
        return cc->Encrypt(kp.publicKey, p);
    }
    double dec(const Ciphertext<DCRTPoly> &ct) {
        Plaintext r; cc->Decrypt(kp.secretKey, ct, &r);
        r->SetLength(1);
        return r->GetRealPackedValue()[0];
    }
    double add(double a, double b) { return dec(cc->EvalAdd(enc(a), enc(b))); }
    double mul(double a, double b) { return dec(cc->EvalMult(enc(a), enc(b))); }
};

int main(int argc, char **argv) {
    long iters = (argc > 1) ? atol(argv[1]) : 200;
    unsigned seed = (argc > 2) ? (unsigned)atol(argv[2]) : 42;
    srand(seed);

    SealCkks *S = SealCkks::create();
    OfheCkks *O = new OfheCkks();

    /* absolute bounds: intrinsic CKKS error ~ magnitude * 2^-30; give head-room
     * so only genuine bugs (not approximation noise) fire. XLIB is the cross-
     * library tolerance between the two independent implementations. */
    const double ADD_BOUND = 1e-2;
    const double MUL_BOUND = 1.0;
    const double XLIB_ADD  = 2e-2;
    const double XLIB_MUL  = 2.0;

    for (long i = 0; i < iters; i++) {
        double a = ((double)(rand() % 20001) - 10000.0) / 100.0; /* [-100,100] */
        double b = ((double)(rand() % 20001) - 10000.0) / 100.0;

        double t_add = a + b, t_mul = a * b;
        double s_add = S->add(a, b), s_mul = S->mul(a, b);
#ifdef CMF_FHE_FAULT
        s_add += 5.0; /* far beyond the bound: prove the differential fires */
#endif
        double o_add = O->add(a, b), o_mul = O->mul(a, b);

        /* each library must be near the true value ... */
        if (std::fabs(s_add - t_add) > ADD_BOUND || std::fabs(o_add - t_add) > ADD_BOUND)
            CMF_VIOLATION(ALG, "O1_ckks_interop", "CKKS add error exceeds bound");
        if (std::fabs(s_mul - t_mul) > MUL_BOUND + 1e-3 * std::fabs(t_mul) ||
            std::fabs(o_mul - t_mul) > MUL_BOUND + 1e-3 * std::fabs(t_mul))
            CMF_VIOLATION(ALG, "O1_ckks_interop", "CKKS mul error exceeds bound");
        /* ... and the two libraries must agree with each other. */
        if (std::fabs(s_add - o_add) > XLIB_ADD)
            CMF_VIOLATION(ALG, "O1_ckks_interop", "SEAL vs OpenFHE CKKS add disagree");
        if (std::fabs(s_mul - o_mul) > XLIB_MUL + 1e-3 * std::fabs(t_mul))
            CMF_VIOLATION(ALG, "O1_ckks_interop", "SEAL vs OpenFHE CKKS mul disagree");
    }
    printf("[fhe-ckks-diff] CKKS OpenFHE<->SEAL: %ld iters, add/mul agree within bounds\n", iters);
    delete S; delete O;
    return 0;
}
