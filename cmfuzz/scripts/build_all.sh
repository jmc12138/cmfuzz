#!/usr/bin/env bash
# One-shot: build target libraries, (re)generate specs, build all harnesses.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/scripts/build_liboqs.sh"
bash "$ROOT/scripts/build_seal.sh"
python3 "$ROOT/spec_gen/generate_specs.py" --liboqs "$ROOT/libs/liboqs" ${CMF_LLM:+--llm}
bash "$ROOT/scripts/build_harness.sh"
# SEAL FHE harness (built separately: C++ + SEAL include/lib paths)
S="$ROOT/libs/SEAL"
clang++ -std=c++17 -fsanitize=fuzzer -g -O1 -I"$S/native/src" -I"$S/build/native/src" \
  "$ROOT/harness/seal_fhe_harness.cpp" "$S/build/lib/"libseal-*.a -o "$ROOT/build/harness/fhe_seal_bfv"
# OpenSSL classic harness
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  "$ROOT/harness/openssl_classic_harness.c" -lcrypto -o "$ROOT/build/harness/classic_openssl"
# Traditional metamorphic harness (round-trip / tamper-reject / chunk-consistency)
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  "$ROOT/harness/trad_metamorphic_harness.c" -lcrypto -o "$ROOT/build/harness/trad_metamorphic"
# L2 composition harness: HPKE-style KEM+KDF+AEAD (X25519 + ML-KEM-768 backends)
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  -DCMF_HPKE_KEM=0 "$ROOT/harness/comp_hpke_harness.c" -lcrypto \
  -o "$ROOT/build/harness/comp_hpke_x25519"
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  -DCMF_HPKE_KEM=1 -I"$ROOT/libs/liboqs/build/include" "$ROOT/harness/comp_hpke_harness.c" \
  "$ROOT/libs/liboqs/build/lib/liboqs.a" -lcrypto -o "$ROOT/build/harness/comp_hpke_mlkem"
# L2 traditional composition: Encrypt-then-MAC (AES-CBC+HMAC) + TLS1.3-style record layer
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  "$ROOT/harness/comp_trad_harness.c" -lcrypto -o "$ROOT/build/harness/comp_trad"
# L2 authenticated KEM (KEM+signature) — classical + PQC backends
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  -DCMF_AK_PQC=0 "$ROOT/harness/comp_authkem_harness.c" -lcrypto \
  -o "$ROOT/build/harness/comp_authkem_classic"
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  -DCMF_AK_PQC=1 -I"$ROOT/libs/liboqs/build/include" "$ROOT/harness/comp_authkem_harness.c" \
  "$ROOT/libs/liboqs/build/lib/liboqs.a" -lcrypto -o "$ROOT/build/harness/comp_authkem_pqc"
# L2 KDF chain / ratchet key schedule
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  "$ROOT/harness/comp_kdfchain_harness.c" -lcrypto -o "$ROOT/build/harness/comp_kdfchain"
# L3 sequence / API-misuse: AEAD nonce-uniqueness + release-before-verify (O6)
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  "$ROOT/harness/seq_aead_harness.c" -lcrypto -o "$ROOT/build/harness/seq_aead"
# L3 sequence / API-misuse: ECDSA per-signature nonce (k) reuse -> key recovery (O6)
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  "$ROOT/harness/seq_ecdsa_harness.c" -lcrypto -o "$ROOT/build/harness/seq_ecdsa"
# L3 sequence / API-misuse: PQC KEM key-confusion (no false agreement) (O6)
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  -I"$ROOT/libs/liboqs/build/include" "$ROOT/harness/seq_pqc_harness.c" \
  "$ROOT/libs/liboqs/build/lib/liboqs.a" -lcrypto -o "$ROOT/build/harness/seq_pqc_kem"
# L3 sequence / API-misuse: CBC IV-unpredictability + EVP ctx use-after-free (O6)
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  "$ROOT/harness/seq_evp_harness.c" -lcrypto -o "$ROOT/build/harness/seq_evp"
# Extra libraries + multi-library differential harness (optional; skipped if the
# extra libs failed to build so a minimal setup still succeeds).
if bash "$ROOT/scripts/build_diff_libs.sh"; then
  bash "$ROOT/scripts/build_diff_harness.sh" || echo "[build_all] diff harness skipped"
fi
# Stage 2.1 subprocess differential (BoringSSL). Optional: needs Go to build
# BoringSSL, so a minimal setup without Go still succeeds.
bash "$ROOT/scripts/build_subproc.sh" || echo "[build_all] subprocess diff skipped (BoringSSL/Go missing)"
# Stage 2.3 PQC cross-library differential (liboqs vs PQClean). Optional.
bash "$ROOT/scripts/build_pqc_diff.sh" || echo "[build_all] PQC diff skipped (PQClean missing)"
# Stage 2.3 PQC deterministic KAT cross-check (byte-exact under shared NIST DRBG).
bash "$ROOT/scripts/build_pqc_kat.sh" || echo "[build_all] PQC KAT skipped (PQClean missing)"
# Stage 2.4 cross-language differential (Go crypto backend). Optional: needs Go.
bash "$ROOT/scripts/build_go_diff.sh" || echo "[build_all] Go cross-lang diff skipped (Go missing)"
# Stage 2.4 cross-language differential (RustCrypto backend). Optional: needs cargo.
bash "$ROOT/scripts/build_rust_diff.sh" || echo "[build_all] Rust cross-lang diff skipped (cargo missing)"
# Stage 2.5 FHE oracles: OpenFHE<->SEAL BFV differential + SEAL CKKS error bound.
# Optional: needs OpenFHE (built on demand by build_fhe_diff.sh).
bash "$ROOT/scripts/build_fhe_diff.sh" || echo "[build_all] FHE diff skipped (OpenFHE/SEAL missing)"
# Stage 3 ecosystem: PyCryptodome cross-language differential (Python, independent
# implementation). Optional: needs python3 + pycryptodome.
bash "$ROOT/scripts/build_py_diff.sh" || echo "[build_all] Python diff skipped (pycryptodome missing)"
# Stage 3 ecosystem: libgcrypt (GnuPG) + nettle (GnuTLS) cross-library
# differentials. Optional: need libgcrypt20-dev / nettle-dev headers.
bash "$ROOT/scripts/build_gcrypt_diff.sh" || echo "[build_all] libgcrypt diff skipped (headers missing)"
bash "$ROOT/scripts/build_nettle_diff.sh" || echo "[build_all] nettle diff skipped (headers missing)"
# Stage 3 ecosystem: Bouncy Castle cross-language differential (Java, independent
# implementation). Optional: needs a JDK (javac/java).
bash "$ROOT/scripts/build_java_diff.sh" || echo "[build_all] Java diff skipped (JDK missing)"
# Stage 3 ecosystem: TFHE-rs homomorphic-integer correctness oracle (Rust FHE,
# independent of SEAL/OpenFHE). Optional + heavy (~2 min first compile): needs cargo.
bash "$ROOT/scripts/build_tfhe.sh" || echo "[build_all] TFHE-rs oracle skipped (cargo missing)"
# Stage 4 exploration: arkworks Groth16 zk-SNARK verify/circuit-consistency
# oracle. Optional: needs cargo.
bash "$ROOT/scripts/build_zk.sh" || echo "[build_all] ZK oracle skipped (cargo missing)"
echo "[build_all] done"
