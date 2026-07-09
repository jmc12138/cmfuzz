// CMFuzz stage 3 — TFHE-rs homomorphic-integer correctness oracle.
//
// TFHE-rs (Zama) is an independent FHE library implementing the TFHE/CGGI scheme
// over encrypted integers — distinct from the SEAL/OpenFHE BFV/CKKS stack of
// stage 2.5. Unlike CKKS, TFHE integer arithmetic is EXACT, so the metamorphic
// oracle is an equality check (like the BFV differential), not an error bound:
//
//   for random u32 a,b:
//     add : Dec(Enc(a) + Enc(b)) == a.wrapping_add(b)
//     sub : Dec(Enc(a) - Enc(b)) == a.wrapping_sub(b)
//     mul : Dec(Enc(a) * Enc(b)) == a.wrapping_mul(b)
//     MR (distributivity): Dec(Enc(a) * (Enc(b)+Enc(c))) == a*(b+c)   (all wrapping)
//
// Any mismatch prints a CMF_VIOLATION line and exits non-zero, so it doubles as a
// self-test under `--features fault` (which corrupts one homomorphic result).
//
// Usage: cmf_tfhe [iters] [seed]   (defaults: 20 iterations, seed 42)

use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

// Tiny deterministic PRNG (splitmix64) so runs are reproducible by seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn u32(&mut self) -> u32 {
        self.next() as u32
    }
}

fn violation(detail: &str) {
    eprintln!(
        "CMF_VIOLATION alg=FHE-tfhe oracle=O_tfhe_int_correctness detail=\"{}\"",
        detail
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iters: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let seed: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(42);
    let mut rng = Rng(seed);

    let config = ConfigBuilder::default().build();
    let (ck, sk) = generate_keys(config);
    set_server_key(sk);

    let mut failures = 0u64;
    for _ in 0..iters {
        let a = rng.u32();
        let b = rng.u32();
        let c = rng.u32();

        let ea = FheUint32::encrypt(a, &ck);
        let eb = FheUint32::encrypt(b, &ck);
        let ec = FheUint32::encrypt(c, &ck);

        let r_add: u32 = (&ea + &eb).decrypt(&ck);
        let r_sub: u32 = (&ea - &eb).decrypt(&ck);
        #[allow(unused_mut)]
        let mut r_mul: u32 = (&ea * &eb).decrypt(&ck);
        let r_dis: u32 = (&ea * (&eb + &ec)).decrypt(&ck);

        #[cfg(feature = "fault")]
        {
            r_mul = r_mul.wrapping_add(1); // corrupt one result beyond the exact oracle
        }

        if r_add != a.wrapping_add(b) {
            violation(&format!("add mismatch a={a} b={b} got={r_add}"));
            failures += 1;
        }
        if r_sub != a.wrapping_sub(b) {
            violation(&format!("sub mismatch a={a} b={b} got={r_sub}"));
            failures += 1;
        }
        if r_mul != a.wrapping_mul(b) {
            violation(&format!("mul mismatch a={a} b={b} got={r_mul}"));
            failures += 1;
        }
        if r_dis != a.wrapping_mul(b.wrapping_add(c)) {
            violation(&format!("distributivity mismatch a={a} b={b} c={c} got={r_dis}"));
            failures += 1;
        }
    }

    if failures > 0 {
        eprintln!("[tfhe] {failures} oracle violation(s) over {iters} iterations");
        std::process::exit(1);
    }
    eprintln!("[tfhe] {iters} iterations: homomorphic integer arithmetic correct");
}
