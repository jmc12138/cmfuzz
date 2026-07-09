/*
 * CMFuzz stage 2.5b — SEAL CKKS approximate-arithmetic error-bound oracle.
 *
 * CKKS is approximate: unlike BFV there is no exact plaintext to match, so an
 * equality oracle is wrong by construction. Instead we bound the approximation
 * error. For random reals a,b in a fixed range and scale 2^40:
 *
 *   add : |Dec(Enc(a)+Enc(b)) - (a+b)| must stay within an absolute error bound
 *   mul : |Dec((Enc(a)*Enc(b)) rescaled) - (a*b)| within a (looser) error bound
 *
 * The bounds are generous multiples of the intrinsic CKKS encoding error
 * (~ magnitude / 2^precision); a result outside them signals a real correctness
 * bug, not ordinary approximation noise. Firing oracle: O2_ckks_error_bound.
 * CMF_FHE_FAULT=1 perturbs a result far beyond the bound so the negative
 * self-test proves the oracle catches a divergent/incorrect backend.
 */
#include "seal/seal.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

extern "C" {
#include "../engine/cmfuzz_common.h"
}

#define ALG "FHE-CKKS"

int main(int argc, char **argv) {
    long iters = (argc > 1) ? atol(argv[1]) : 200;
    unsigned seed = (argc > 2) ? (unsigned)atol(argv[2]) : 42;
    srand(seed);

    using namespace seal;
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly = 8192;
    parms.set_poly_modulus_degree(poly);
    parms.set_coeff_modulus(CoeffModulus::Create(poly, {60, 40, 40, 60}));
    double scale = std::pow(2.0, 40);

    SEALContext ctx(parms);
    KeyGenerator keygen(ctx);
    SecretKey sk = keygen.secret_key();
    PublicKey pk; keygen.create_public_key(pk);
    RelinKeys relin; keygen.create_relin_keys(relin);

    CKKSEncoder encoder(ctx);
    Encryptor encryptor(ctx, pk);
    Evaluator eval(ctx);
    Decryptor decryptor(ctx, sk);

    auto enc = [&](double x) {
        Plaintext pt; encoder.encode(x, scale, pt);
        Ciphertext ct; encryptor.encrypt(pt, ct); return ct;
    };
    auto dec = [&](const Ciphertext &ct) -> double {
        Plaintext pt; decryptor.decrypt(ct, pt);
        std::vector<double> v; encoder.decode(pt, v); return v[0];
    };

    /* absolute error bounds: intrinsic CKKS error ~ magnitude * 2^-30 here; give
     * plenty of head-room so only genuine bugs (not noise) fire. */
    const double ADD_BOUND = 1e-2;
    const double MUL_BOUND = 1.0;

    for (long i = 0; i < iters; i++) {
        double a = ((double)(rand() % 20001) - 10000.0) / 100.0; /* [-100,100] */
        double b = ((double)(rand() % 20001) - 10000.0) / 100.0;

        Ciphertext ca = enc(a), cb = enc(b);
        Ciphertext csum; eval.add(ca, cb, csum);
        double r_add = dec(csum);

        Ciphertext cprod; eval.multiply(ca, cb, cprod);
        eval.relinearize_inplace(cprod, relin);
        eval.rescale_to_next_inplace(cprod);
        double r_mul = dec(cprod);
#ifdef CMF_FHE_FAULT
        r_add += 5.0; /* far beyond ADD_BOUND: prove the error-bound oracle fires */
#endif
        if (std::fabs(r_add - (a + b)) > ADD_BOUND)
            CMF_VIOLATION(ALG, "O2_ckks_error_bound", "CKKS add error exceeds bound");
        if (std::fabs(r_mul - (a * b)) > MUL_BOUND + 1e-3 * std::fabs(a * b))
            CMF_VIOLATION(ALG, "O2_ckks_error_bound", "CKKS mul error exceeds bound");
    }
    printf("[fhe-ckks] SEAL CKKS: %ld iters, add/mul within error bound\n", iters);
    return 0;
}
