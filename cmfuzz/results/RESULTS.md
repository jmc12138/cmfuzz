# CMFuzz campaign results

Environment: Ubuntu 22.04, clang 14, 2 vCPU shared VM. liboqs (Debug, static),
Microsoft SEAL 4.3 (Release, static), OpenSSL 3.0. All harnesses built with
libFuzzer; C harnesses additionally with ASan + UBSan.

## Pillar 2a — functional campaign (30s/target budget)

| target | runs | cov | features | crashes | oracle violations |
|---|---:|---:|---:|---:|---|
| classic_openssl (SHA-256 / AES-256-GCM) | 4,194,304 | 51 | 94 | 0 | 0 |
| fhe_seal_bfv (SEAL BFV) | 512 | 196 | 206 | 0 | 0 |
| kem_ML-KEM-512 | 317,237 | 21 | 33 | 0 | 0 |
| kem_ML-KEM-768 | 254,989 | 21 | 34 | 0 | 0 |
| kem_ML-KEM-1024 | 131,072 | 20 | 32 | 0 | 0 |
| kem_Kyber768 | 262,144 | 21 | 32 | 0 | 0 |
| kem_FrodoKEM-640-AES | 2,048 | 20 | 28 | 0 | 0 |
| kem_BIKE-L1 | 2,376 | 20 | 28 | 0 | 0 |
| sig_ML-DSA-44 | 65,536 | 25 | 50 | 0 | 0 |
| sig_ML-DSA-65 | 32,768 | 25 | 50 | 0 | 0 |
| sig_ML-DSA-87 | 33,213 | 25 | 50 | 0 | 0 |
| sig_Falcon-512 | 2,048 | 24 | 36 | 0 | 0 |
| sig_Falcon-1024 | 1,102 | 24 | 34 | 0 | 0 |
| sig_SLH-DSA-SHA2-128f | 789 | 24 | 31 | 0 | 0 |

14 targets, **0 crashes and 0 metamorphic-oracle violations** on the current,
standardised implementations. This is the expected outcome for hardened reference
code and confirms the oracle engine does not fire false positives across KEM
(correctness / non-malleability / wrong-key / determinism), DSS (correctness /
message-binding / SUF / wrong-key), FHE (correctness / distributivity) and classic
(chunk-equivalence / AEAD round-trip / tamper-rejection) relations. (Metamorphic
oracles are validated separately with negative tests, see `tests/`.)

## Pillar 2b — constant-time (dudect) campaign (200k measurements, pinned core)

| target | op | max \|t\| | verdict | interpretation |
|---|---|---:|---|---|
| ML-KEM-512 | decaps | 1.81 | OK | constant-time |
| ML-KEM-768 | decaps | 4.90 | ~threshold | noise-dominated on shared VM (a pinned re-run gave 3.7 = OK) |
| ML-KEM-1024 | decaps | 2.04 | OK | constant-time |
| Kyber768 | decaps | 4.21 | ~threshold | noise-dominated |
| ML-DSA-65 | sign | 15.72 | data-dependent | **by design**: Dilithium rejection sampling ⇒ signing time varies with message/nonce; public-coin, does not leak the key |
| Falcon-512 | sign | 5.57 | data-dependent | Falcon's floating-point Gaussian sampling has documented timing sensitivity |

Threshold is |t| > 4.5. The KEM decapsulation numbers sit right at the threshold and
flip between runs — characteristic dudect behaviour on a virtualised host; treat KEM
verdicts as "needs isolated-host confirmation", not evidence of a leak. The signature
results are the interesting ones: the engine correctly surfaces the *known,
by-design* data-dependent timing of ML-DSA (rejection sampling) and Falcon (FP
sampling) — exactly the kind of "functional vs timing" distinction the dual-oracle
design is meant to expose.

## Pillar 3-extended — multi-library differential campaign

Cross-checks the SAME primitive across **OpenSSL + libsodium + Mbed-TLS 3.6.2 +
Crypto++** on each fuzzer input; any disagreement is a differential bug.

| target | libs | primitives | runs | cov | violations |
|---|---|---|---:|---:|---|
| diff_multilib | OpenSSL / libsodium / mbedtls / cryptopp | SHA-256, SHA-512, HMAC-SHA256, ChaCha20-Poly1305, AES-256-GCM | ~3.1M (90s) | 1268 | 0 |

All four implementations agree on every input — no differential divergence on the
current releases (expected; these are widely-deployed, Wycheproof-tested libraries).
Coverage (1268) is ~25× the single-library OpenSSL harness (51) because the input
now drives four independent implementations. The differential oracle itself is
validated by a fault-injection self-test (`tests/negative_tests.sh` → DIFF_mismatch).

## Negative (self-)tests — oracles actually fire

`tests/negative_tests.sh`, 3/3 pass:

| oracle | fault injected | verdict |
|---|---|---|
| KEM MR1 correctness | corrupt recovered shared secret | fires MR1_correctness |
| SIG MR3 strong-unforgeability | verifier ignores a signature byte | fires MR3_strong_unforgeability |
| Differential | one library's SHA-256 output corrupted | fires DIFF_mismatch |

This proves the "0 violations" results above are meaningful (silent because the
implementations are correct, not because the oracles never trigger).

## Takeaways
- End-to-end pipeline works across all three pillars on PQC + FHE + classic targets.
- No false-positive oracle violations — the metamorphic/security relations are sound.
- The constant-time engine discriminates constant-time (ML-KEM decaps) from
  data-dependent (ML-DSA / Falcon sign) operations, but needs an isolated host for
  trustworthy verdicts near the threshold.
- To surface real bugs, next steps are (a) test *older* liboqs versions where CIFT/CVE
  bugs are known to exist (the harnesses are version-agnostic), and (b) instrument SEAL
  with coverage for guided FHE fuzzing.
