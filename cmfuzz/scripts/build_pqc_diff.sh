#!/usr/bin/env bash
# Build the stage 2.3 PQC cross-library differential (liboqs vs PQClean).
# Links liboqs.a + libpqclean.a in one binary (PQClean symbols are namespaced,
# so there is no clash). ASan/UBSan on to catch parsing bugs in either backend.
# CMF_PQC_FAULT (any 2nd arg) builds the fault-injected self-test variant.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OQS="$ROOT/libs/liboqs"
PQC="$ROOT/libs/pqclean"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

[ -f "$PQC/build/libpqclean.a" ] || bash "$ROOT/scripts/build_pqclean.sh"

CC=clang
SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g -O1"
INC="-I$OQS/build/include"
FAULT="${1:-}"
DEF=""; BIN="$OUT/pqc_diff"
if [ -n "$FAULT" ]; then DEF="-DCMF_PQC_FAULT=1"; BIN="$OUT/pqc_diff_fault"; fi

$CC $SAN $INC $DEF "$ROOT/harness/pqc_diff_harness.c" \
    "$OQS/build/lib/liboqs.a" "$PQC/build/libpqclean.a" \
    -lcrypto -lpthread -ldl -o "$BIN"
echo "[build] pqc_diff -> $BIN"
