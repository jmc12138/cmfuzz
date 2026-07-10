#!/usr/bin/env bash
# Build the PQC deterministic KAT cross-check (liboqs vs PQClean under a shared
# NIST AES-256-CTR-DRBG). nistkatrng.c defines the global `randombytes`, so it
# is linked as a direct object *before* libpqclean.a — the archive's own
# randombytes.o is then never pulled (archive members resolve on demand only),
# avoiding a duplicate-symbol clash. liboqs draws from the same DRBG via its
# runtime custom-RNG hook. CMF_KAT_FAULT (any 1st extra arg) builds the
# fault-injected self-test variant.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OQS="$ROOT/libs/liboqs"
PQC="$ROOT/libs/pqclean"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

[ -f "$PQC/build/libpqclean.a" ] || bash "$ROOT/scripts/build_pqclean.sh"

CC=clang
SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g -O1"
INC="-I$OQS/build/include -I$PQC/common"
FAULT="${1:-}"
DEF=""; BIN="$OUT/pqc_kat"
if [ -n "$FAULT" ]; then DEF="-DCMF_KAT_FAULT=1"; BIN="$OUT/pqc_kat_fault"; fi

# Direct objects providing the NIST DRBG + its AES backend (global randombytes).
$CC $SAN $INC -c "$PQC/common/aes.c"            -o "$OUT/kat_aes.o"
$CC $SAN $INC -c "$PQC/test/common/nistkatrng.c" -o "$OUT/kat_rng.o"

$CC $SAN $INC $DEF "$ROOT/harness/pqc_kat_harness.c" \
    "$OUT/kat_rng.o" "$OUT/kat_aes.o" \
    "$OQS/build/lib/liboqs.a" "$PQC/build/libpqclean.a" \
    -lcrypto -lpthread -ldl -o "$BIN"
echo "[build] pqc_kat -> $BIN"
