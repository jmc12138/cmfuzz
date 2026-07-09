#!/usr/bin/env bash
# Build the stage 2.4 cross-language differential: the OpenSSL-reference
# subprocess runner (diff_subproc) plus a Go crypto backend that speaks the same
# wire protocol. Passing any arg builds the fault-injected Go backend variant
# (faultMode=1) used by the negative self-test.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUB="$ROOT/harness/subproc"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

# Runner (OpenSSL reference). Shared with the stage 2.1 subprocess differential.
clang -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$OUT/diff_subproc"

FAULT="${1:-}"
LD=""; BIN="$OUT/compute_go"
if [ -n "$FAULT" ]; then LD="-X main.faultMode=1"; BIN="$OUT/compute_go_fault"; fi

( cd "$ROOT/harness/gobridge" && GOFLAGS=-mod=mod go build -ldflags "$LD" -o "$BIN" . )
echo "[build] go cross-language backend -> $BIN"
