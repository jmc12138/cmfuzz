# CMFuzz design

CMFuzz operationalises the "next step after CLFuzz" as three cooperating pillars that
share one spec model and one input generator.

```
                      specs/*.json  (Pillar 1 output)
                            │
        ┌───────────────────┼────────────────────────┐
        │                   │                         │
  spec_gen/ (LLM or     harness/ (Pillar 3)      engine/ct_dudect.c
  offline templates)    structure-aware libFuzzer  (Pillar 2: timing)
        │               targets, oracles embedded        │
        │                   │                         │
        └──── functional oracle engine (Pillar 2: correctness) ┘
```

## Pillar 1 — spec + oracle generation (`spec_gen/`, `specs/`)
CLFuzz manually encodes, per algorithm, the input constraints and the function signature
used to drive generation and cross-checking. CMFuzz makes that a generated artefact:

- `generate_specs.py` enumerates every algorithm exposed by a target library (parsing
  `OQS_{KEM,SIG}_alg_*` identifiers from liboqs headers) and emits one JSON spec each.
- Each spec records the **function signature**, **input constraints** (lengths, which
  bytes are attacker-controlled) and a list of **oracles** derived from the security
  notion (IND-CCA2 ⇒ ciphertext non-malleability; EUF/SUF-CMA ⇒ message-binding /
  signature non-malleability).
- `llm_client.py` is a pluggable LLM backend: with `OPENAI_API_KEY`/`DEEPSEEK_API_KEY`
  set, specs are extracted by prompting an LLM with the header + notion; otherwise the
  offline, kind-specific templates are used. Either way the downstream pipeline is
  identical — the LLM removes the per-algorithm manual cost without being a hard
  dependency.

262 specs are generated for liboqs (41 KEM + 221 SIG) out of the box.

## Pillar 2 — dual detection (functional + constant-time)
- **Functional oracle engine**: metamorphic relations + self-differential checks +
  memory safety. Encoded directly in the harnesses as `CMF_VIOLATION` assertions
  (logical bugs) plus ASan/UBSan (memory/UB bugs). Relations per kind:
  - KEM: correctness round-trip, decaps determinism, ciphertext non-malleability,
    wrong-key separation, attacker-controlled-ciphertext memory safety.
  - SIG: correctness, message-binding (EUF), signature non-malleability (SUF —
    the property CIFT found violated by Falcon's compressed format), wrong-key,
    attacker-controlled-signature memory safety.
  - FHE: homomorphic correctness vs plaintext domain, distributivity via
    equivalence-expression transformation.
  - Classic: digest chunk-vs-one-shot equivalence, AEAD round-trip, AEAD tamper
    rejection.
- **Constant-time engine** (`engine/ct_dudect.c`): a dudect-style leakage test on the
  same algorithms. Two input classes (fixed vs random), cycle-accurate `rdtscp`
  measurement, Welch t-test with percentile cropping; `|t| > 4.5 ⇒ LEAK`. Kept as a
  separate binary because coverage instrumentation perturbs timing. Both halves are
  driven by the same specs (`constant_time` block names the secret-dependent target).

The novelty is that a single generator/spec feeds *both* oracles — existing crypto
fuzzers do functional **or** timing, not both.

## Pillar 3 — PQC / FHE / classic coverage (`harness/`)
- `liboqs_kem_harness.c` / `liboqs_sig_harness.c`: one libFuzzer binary per algorithm
  (`-DCMF_KEM_ALG` / `-DCMF_SIG_ALG`), so a crash localises to an algorithm.
- `seal_fhe_harness.cpp`: Microsoft SEAL BFV homomorphic-correctness testing.
- `openssl_classic_harness.c`: traditional AEAD/digest via OpenSSL EVP.

## Reproducibility of inputs
`engine/cmfuzz_common.h` overrides liboqs' RNG (`OQS_randombytes_custom_algorithm`) with
a SplitMix64 stream seeded from the fuzzer buffer, so key generation / encapsulation
become a deterministic function of the input — crashing inputs replay exactly and the
metamorphic relations hold by construction.

## Known limitations
- The dudect timing verdict is noise-sensitive on shared/virtualised hosts; CMFuzz pins
  to a single core (`taskset -c 0`) but a leak verdict should be reproduced on an
  isolated machine before being trusted (e.g. Falcon-512 sign sits near the threshold).
- The SEAL FHE target is not coverage-instrumented (SEAL is linked as a prebuilt static
  lib), so the FHE harness runs as a seeded property tester rather than coverage-guided.
- HQC and some SLH-DSA parameter sets are disabled in the default liboqs build.
