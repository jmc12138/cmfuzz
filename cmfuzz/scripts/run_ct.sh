#!/usr/bin/env bash
# Build & run the constant-time (dudect) engine for selected algorithms.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OQS="$ROOT/libs/liboqs"
OUT="$ROOT/build/ct"; mkdir -p "$OUT"
RES="$ROOT/results/ct"; mkdir -p "$RES"
INC="-I$OQS/build/include"; LIB="$OQS/build/lib/liboqs.a"; EXTRA="-lcrypto -lpthread -ldl -lm"

# KEM decaps targets (kind 0) and SIG sign targets (kind 1)
KEMS=("ML-KEM-512" "ML-KEM-768" "ML-KEM-1024" "Kyber768")
SIGS=("ML-DSA-65" "Falcon-512")

run_one() {
  local kind="$1" alg="$2" opname="$3"
  local safe="${alg//[^A-Za-z0-9_.-]/_}"
  local bin="$OUT/ct_${opname}_${safe}"
  clang -O2 -g $INC -DCMF_ALG="\"$alg\"" -DCMF_KIND=$kind "$ROOT/engine/ct_dudect.c" "$LIB" $EXTRA -o "$bin"
  echo "[ct] running $opname $alg ..."
  # pin to one core to reduce scheduling/frequency noise (dudect needs low jitter)
  taskset -c 0 "$bin" | tee -a "$RES/ct_results.txt"
}

: > "$RES/ct_results.txt"
for k in "${KEMS[@]}"; do run_one 0 "$k" decaps; done
for s in "${SIGS[@]}"; do run_one 1 "$s" sign; done

# Traditional-algorithm constant-time targets (orthogonal to PQC): AES-NI block
# encrypt, constant-time vs naive tag compare.
for op in 0 1 2; do
  bin="$OUT/ct_trad_$op"
  clang -O2 -Wno-deprecated-declarations -DCMF_TRAD_OP=$op "$ROOT/engine/ct_dudect_trad.c" -lcrypto -lm -o "$bin"
  echo "[ct] running traditional op=$op ..."
  taskset -c 0 "$bin" | tee -a "$RES/ct_results.txt"
done
echo "[ct] results -> $RES/ct_results.txt"
