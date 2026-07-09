#!/usr/bin/env bash
# Build the stage-4 arkworks Groth16 zk-SNARK oracle (harness/zkbridge). This is
# the ZK exploration: a proof-verification / circuit-consistency oracle checking
# Groth16 completeness + soundness over BN254 — a bug class the classical/FHE
# oracles do not cover.
#
# Requires a Rust toolchain (cargo). Passing any argument also builds the
# fault-injected variant (--features fault) used by the negative self-test.
# Build artifacts are gitignored; Cargo.lock is committed to pin versions.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/harness/zkbridge"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

cargo build --release --manifest-path "$DIR/Cargo.toml"
cp "$DIR/target/release/cmf_zk" "$OUT/cmf_zk"
echo "[build] cmf_zk -> $OUT/cmf_zk"

if [ -n "${1:-}" ]; then
  cargo build --release --features fault --manifest-path "$DIR/Cargo.toml"
  cp "$DIR/target/release/cmf_zk" "$OUT/cmf_zk_fault"
  echo "[build] cmf_zk_fault -> $OUT/cmf_zk_fault"
  # Restore the clean (non-fault) binary so later steps use the honest verifier.
  cargo build --release --manifest-path "$DIR/Cargo.toml"
  cp "$DIR/target/release/cmf_zk" "$OUT/cmf_zk"
fi
