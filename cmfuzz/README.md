# CMFuzz — Cryptographically-informed Metamorphic Fuzzer

A semantic-aware fuzzing framework for cryptographic-library implementations that unifies
three pillars proposed as the next step after CLFuzz:

1. **Spec + oracle driven (LLM-assisted)** — each algorithm is described by a machine-readable
   *spec* (input constraints + function signature) and a set of *metamorphic oracles*
   (correctness round-trips, malleability, key/nonce misuse). Specs can be generated offline
   or by an LLM from headers/standards (`spec_gen/`), matching CLFuzz's semantic extraction
   but removing the per-algorithm manual cost.
2. **Dual detection: functional + constant-time** — a single input generator feeds both a
   *functional oracle engine* (metamorphic + differential + memory safety via ASan/UBSan) and
   a *constant-time timing oracle* (dudect-style Welch t-test on secret-dependent operations).
   Existing crypto fuzzers only do one or the other.
3. **PQC / FHE / multi-library coverage** — first-class harnesses for post-quantum KEM/DSS
   (liboqs: ML-KEM/Kyber, ML-DSA/Dilithium, Falcon, SLH-DSA) and fully-homomorphic encryption
   (Microsoft SEAL: BFV/CKKS), plus a **multi-library differential harness** cross-checking the
   same primitive across **OpenSSL, libsodium, Mbed-TLS and Crypto++** (SHA-256/512,
   HMAC-SHA256, ChaCha20-Poly1305, AES-256-GCM).

Target libraries chosen from a survey of what other crypto-fuzzing work targets and the most
popular crypto libraries on GitHub — see `docs/TARGET_SURVEY.md`.

## Layout
```
specs/            Pillar 1: per-algorithm JSON specs (constraints, signature, oracles)
spec_gen/         Pillar 1: spec generator (offline heuristics + pluggable LLM backend)
harness/          Pillar 3: C/C++ fuzz drivers per library (structure-aware, oracle-embedded)
engine/           Pillar 2: shared oracle helpers + dudect constant-time engine
scripts/          build/run campaign scripts
results/          campaign logs, crashes, timing verdicts
libs/             third-party target libraries (liboqs, SEAL, ...) — built locally
```

## Build & run
```
scripts/build_liboqs.sh        # build target lib (static, Debug)
scripts/build_harness.sh       # build all liboqs harnesses (libFuzzer + ASan/UBSan)
scripts/build_diff_libs.sh     # build libsodium + Mbed-TLS + Crypto++ (instrumented)
scripts/build_diff_harness.sh  # build the multi-library differential harness
scripts/build_all.sh           # one-shot: everything above
scripts/run_campaign.sh        # run functional fuzzing campaigns (all harnesses)
scripts/run_ct.sh              # run constant-time (dudect) checks
tests/negative_tests.sh        # prove the oracles fire on injected faults
```
See `docs`/inline comments for the spec schema and oracle semantics.
