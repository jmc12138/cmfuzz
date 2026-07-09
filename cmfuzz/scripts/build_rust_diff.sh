#!/usr/bin/env bash
# Build the stage 2.4 cross-language differential: the OpenSSL-reference
# subprocess runner (diff_subproc) plus a RustCrypto backend that speaks the same
# wire protocol. Passing any arg builds the fault-injected Rust backend variant
# (--features fault) used by the negative self-test.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUB="$ROOT/harness/subproc"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

# Runner (OpenSSL reference). Shared with the stage 2.1 subprocess differential.
clang -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$OUT/diff_subproc"

FAULT="${1:-}"
FEAT=""; BIN="$OUT/compute_rust"
if [ -n "$FAULT" ]; then FEAT="--features fault"; BIN="$OUT/compute_rust_fault"; fi

( cd "$ROOT/harness/rustbridge" && cargo build --release $FEAT )
cp "$ROOT/harness/rustbridge/target/release/compute_rust" "$BIN"
echo "[build] rust cross-language backend -> $BIN"
