#!/usr/bin/env bash
# Build the stage-3 TFHE-rs homomorphic-integer correctness oracle
# (harness/tfhebridge). TFHE-rs (Zama) is a Rust-native FHE library implementing
# the TFHE/CGGI scheme over encrypted integers — an independent lineage distinct
# from the SEAL/OpenFHE BFV/CKKS stack of stage 2.5. Because TFHE integer
# arithmetic is exact, the oracle is an equality metamorphic check.
#
# Requires a Rust toolchain (cargo). Passing any argument also builds the
# fault-injected variant (--features fault) used by the negative self-test.
# The tfhe crate is heavy (~2 min first compile); build artifacts are gitignored.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/harness/tfhebridge"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

cargo build --release --manifest-path "$DIR/Cargo.toml"
cp "$DIR/target/release/cmf_tfhe" "$OUT/cmf_tfhe"
echo "[build] cmf_tfhe -> $OUT/cmf_tfhe"

if [ -n "${1:-}" ]; then
  cargo build --release --features fault --manifest-path "$DIR/Cargo.toml"
  cp "$DIR/target/release/cmf_tfhe" "$OUT/cmf_tfhe_fault"
  echo "[build] cmf_tfhe_fault -> $OUT/cmf_tfhe_fault"
  # Restore the clean (non-fault) binary so later steps use the honest oracle.
  cargo build --release --manifest-path "$DIR/Cargo.toml"
  cp "$DIR/target/release/cmf_tfhe" "$OUT/cmf_tfhe"
fi
