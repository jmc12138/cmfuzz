// CMFuzz stage 4 — arkworks Groth16 zk-SNARK verification / circuit-consistency
// oracle (BN254).
//
// This targets a bug class the classical/FHE oracles do not: the soundness and
// completeness of a zero-knowledge proof system. We use a tiny R1CS circuit that
// proves knowledge of a factorization  a * b = c  (a, b private witnesses, c the
// public input), run Groth16 setup/prove/verify, and check the metamorphic
// relations a correct SNARK verifier must satisfy:
//
//   completeness : verify(vk, [c],    honest_proof)      == accept
//   soundness-1  : verify(vk, [c+1],  honest_proof)      == reject  (wrong public input)
//   soundness-2  : verify(vk, [c],    other_proof)       == reject  (proof for another stmt)
//
// Any violated relation prints CMF_VIOLATION ... oracle=O_zk_groth16_verify and
// exits non-zero. Under `--features fault` the completeness result is inverted to
// emulate a broken verifier, so the negative self-test proves the oracle fires.
//
// Usage: cmf_zk [iters] [seed]   (defaults: 5 iterations, seed 42)

use ark_bn254::{Bn254, Fr};
use ark_ff::{One, UniformRand};
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

// Proves knowledge of a, b such that a * b == c, with c a public input.
#[derive(Clone)]
struct MulCircuit {
    a: Option<Fr>,
    b: Option<Fr>,
    c: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MulCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        Ok(())
    }
}

fn violation(detail: &str) {
    eprintln!(
        "CMF_VIOLATION alg=ZK-groth16 oracle=O_zk_groth16_verify detail=\"{}\"",
        detail
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iters: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let seed: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(42);
    let mut rng = StdRng::seed_from_u64(seed);

    // Groth16 setup is circuit-specific but value-independent, so do it once.
    let setup_circuit = MulCircuit { a: None, b: None, c: None };
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).expect("setup");
    let pvk = Groth16::<Bn254>::process_vk(&vk).expect("process_vk");

    let mut failures = 0u64;
    for _ in 0..iters {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a * b;

        let proof = Groth16::<Bn254>::prove(
            &pk,
            MulCircuit { a: Some(a), b: Some(b), c: Some(c) },
            &mut rng,
        )
        .expect("prove");

        // A second, independent statement (different c) for the soundness check.
        let a2 = Fr::rand(&mut rng);
        let b2 = Fr::rand(&mut rng);
        let c2 = a2 * b2;
        let proof2 = Groth16::<Bn254>::prove(
            &pk,
            MulCircuit { a: Some(a2), b: Some(b2), c: Some(c2) },
            &mut rng,
        )
        .expect("prove2");

        #[allow(unused_mut)]
        let mut completeness =
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[c], &proof).expect("verify");
        let sound_wrong_pub =
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[c + Fr::one()], &proof)
                .expect("verify");
        let sound_wrong_stmt =
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[c], &proof2).expect("verify");

        #[cfg(feature = "fault")]
        {
            completeness = !completeness; // emulate a broken verifier
        }

        if !completeness {
            violation("completeness: honest proof rejected by verifier");
            failures += 1;
        }
        if sound_wrong_pub {
            violation("soundness: proof accepted under wrong public input c+1");
            failures += 1;
        }
        if sound_wrong_stmt {
            violation("soundness: proof for a different statement accepted");
            failures += 1;
        }
    }

    if failures > 0 {
        eprintln!("[zk] {failures} oracle violation(s) over {iters} iterations");
        std::process::exit(1);
    }
    eprintln!("[zk] {iters} iterations: Groth16 completeness + soundness relations hold");
}
