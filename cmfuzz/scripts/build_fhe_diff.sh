#!/usr/bin/env bash
# Build the stage 2.5 FHE oracles:
#   fhe_diff  — OpenFHE vs SEAL BFV cross-library differential (O1)
#   fhe_ckks  — SEAL CKKS approximate-arithmetic error-bound oracle (O2)
# Passing any argument builds the fault-injected self-test variants.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEAL="$ROOT/libs/SEAL"
OFHE="$ROOT/libs/openfhe"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

[ -f "$SEAL/build/lib/"libseal-*.a ] || bash "$ROOT/scripts/build_seal.sh"
[ -f "$OFHE/build/lib/libOPENFHEpke_static.a" ] || bash "$ROOT/scripts/build_openfhe.sh"

CXX="${CXX:-g++}"
SEAL_INC="-I$SEAL/native/src -I$SEAL/build/native/src"
SEAL_LIB=("$SEAL/build/lib/"libseal-*.a)

OFHE_ROOT="$OFHE/install/include/openfhe"
OFHE_INC="-I$OFHE_ROOT -I$OFHE_ROOT/core -I$OFHE_ROOT/pke -I$OFHE_ROOT/binfhe -I$OFHE_ROOT/cereal"
OFHE_LIB="$OFHE/build/lib/libOPENFHEpke_static.a $OFHE/build/lib/libOPENFHEcore_static.a"

FAULT="${1:-}"
DEF=""; SFX=""
if [ -n "$FAULT" ]; then DEF="-DCMF_FHE_FAULT=1"; SFX="_fault"; fi

# OpenFHE ships with OpenMP; -fopenmp keeps its parallel regions happy.
$CXX -std=c++17 -O2 -fopenmp $DEF $SEAL_INC $OFHE_INC \
    "$ROOT/harness/fhe_diff_harness.cpp" \
    $OFHE_LIB "${SEAL_LIB[@]}" -lpthread -o "$OUT/fhe_diff$SFX"
echo "[build] fhe_diff -> $OUT/fhe_diff$SFX"

$CXX -std=c++17 -O2 $DEF $SEAL_INC \
    "$ROOT/harness/fhe_ckks_harness.cpp" \
    "${SEAL_LIB[@]}" -lpthread -o "$OUT/fhe_ckks$SFX"
echo "[build] fhe_ckks -> $OUT/fhe_ckks$SFX"
