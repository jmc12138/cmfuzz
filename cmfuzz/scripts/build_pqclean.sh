#!/usr/bin/env bash
# Build a static libpqclean.a with every parameter set of the two NIST-
# standardised lattice schemes we differential-test against liboqs:
# ML-KEM-512/768/1024 (FIPS 203) and ML-DSA-44/65/87 (FIPS 204), all the
# reference "clean" implementations. PQClean namespaces every symbol per
# scheme (PQCLEAN_MLKEM768_CLEAN_*, PQCLEAN_MLDSA65_CLEAN_*, ...), so the
# archive links cleanly alongside liboqs in one differential binary.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PQC="$ROOT/libs/pqclean"
[ -d "$PQC" ] || git clone --depth 1 https://github.com/PQClean/PQClean.git "$PQC"

OUT="$PQC/build"
mkdir -p "$OUT"
CC=${CC:-clang}
CFLAGS="-O2 -fPIC -I$PQC/common"

srcs=(
  "$PQC"/common/fips202.c
  "$PQC"/common/randombytes.c
  "$PQC"/crypto_kem/ml-kem-512/clean/*.c
  "$PQC"/crypto_kem/ml-kem-768/clean/*.c
  "$PQC"/crypto_kem/ml-kem-1024/clean/*.c
  "$PQC"/crypto_sign/ml-dsa-44/clean/*.c
  "$PQC"/crypto_sign/ml-dsa-65/clean/*.c
  "$PQC"/crypto_sign/ml-dsa-87/clean/*.c
)

objs=()
for s in ${srcs[@]}; do
  o="$OUT/$(echo "$s" | md5sum | cut -c1-16).o"
  $CC $CFLAGS -c "$s" -o "$o"
  objs+=("$o")
done

ar rcs "$OUT/libpqclean.a" "${objs[@]}"
echo "[pqclean] built -> $OUT/libpqclean.a"
