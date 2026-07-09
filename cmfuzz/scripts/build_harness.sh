#!/usr/bin/env bash
# Build CMFuzz libFuzzer harnesses (ASan + UBSan) for a selected set of algorithms.
# One binary per algorithm so a crash isolates the algorithm under test.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OQS="$ROOT/libs/liboqs"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

CC=clang
SAN="-fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1"
INC="-I$OQS/build/include"
LIB="$OQS/build/lib/liboqs.a"
# liboqs (default build) links against OpenSSL's libcrypto
EXTRA="-lcrypto -lpthread -ldl"

# Default selection (override by passing "KEM:alg" / "SIG:alg" args)
KEMS=("ML-KEM-512" "ML-KEM-768" "ML-KEM-1024" "Kyber768" "FrodoKEM-640-AES" "BIKE-L1")
SIGS=("ML-DSA-44" "ML-DSA-65" "ML-DSA-87" "Falcon-512" "Falcon-1024" "SLH_DSA_PURE_SHA2_128F")

if [ "$#" -gt 0 ]; then
  KEMS=(); SIGS=()
  for a in "$@"; do
    case "$a" in
      KEM:*) KEMS+=("${a#KEM:}") ;;
      SIG:*) SIGS+=("${a#SIG:}") ;;
    esac
  done
fi

build_one() {
  local kind="$1" alg="$2" src="$3" macro="$4"
  local safe="${alg//[^A-Za-z0-9_.-]/_}"
  local bin="$OUT/${kind}_${safe}"
  echo "[build] $kind $alg -> $(basename "$bin")"
  $CC $SAN $INC -D"$macro"="\"$alg\"" "$ROOT/$src" "$LIB" $EXTRA -o "$bin"
}

for k in "${KEMS[@]}"; do build_one kem "$k" harness/liboqs_kem_harness.c CMF_KEM_ALG; done
for s in "${SIGS[@]}"; do build_one sig "$s" harness/liboqs_sig_harness.c CMF_SIG_ALG; done
echo "[build] done -> $OUT"
ls -1 "$OUT"
