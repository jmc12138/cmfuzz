#!/usr/bin/env bash
# Build the stage-3 libgcrypt cross-library differential (libgcrypt vs OpenSSL).
# libgcrypt (GnuPG's crypto core) is an independent implementation, so byte-exact
# agreement with the OpenSSL reference is a real O1 differential.
#
# Requires the libgcrypt development headers (Debian/Ubuntu: libgcrypt20-dev).
# Builds the OpenSSL reference runner (if absent) and the standalone libgcrypt
# compute CLI. Passing any argument also builds the fault-injected variant.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUB="$ROOT/harness/subproc"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

CC="${CC:-cc}"
GCRYPT_CFG="${LIBGCRYPT_CONFIG:-libgcrypt-config}"
if command -v "$GCRYPT_CFG" >/dev/null 2>&1; then
  GCR_CFLAGS="$($GCRYPT_CFG --cflags)"
  GCR_LIBS="$($GCRYPT_CFG --libs)"
else
  GCR_CFLAGS=""
  GCR_LIBS="-lgcrypt -lgpg-error"
fi

[ -x "$OUT/diff_subproc" ] || $CC -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$OUT/diff_subproc"

$CC -g -O1 $GCR_CFLAGS "$SUB/compute_libgcrypt.c" -I"$SUB" $GCR_LIBS -o "$OUT/compute_libgcrypt"
echo "[build] compute_libgcrypt -> $OUT/compute_libgcrypt"

if [ -n "${1:-}" ]; then
  $CC -g -O1 -DCMF_DIFF_FAULT=1 $GCR_CFLAGS "$SUB/compute_libgcrypt.c" -I"$SUB" $GCR_LIBS -o "$OUT/compute_libgcrypt_fault"
  echo "[build] compute_libgcrypt_fault -> $OUT/compute_libgcrypt_fault"
fi
