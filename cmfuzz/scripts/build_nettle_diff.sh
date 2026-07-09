#!/usr/bin/env bash
# Build the stage-3 nettle cross-library differential (nettle vs OpenSSL).
# nettle (GnuTLS's low-level crypto core) is an independent implementation, so
# byte-exact agreement with the OpenSSL reference is a real O1 differential.
#
# Requires the nettle development headers (Debian/Ubuntu: nettle-dev). Only
# libnettle is needed (ops 0-12 avoid the GMP-based hogweed). Builds the OpenSSL
# reference runner (if absent) and the standalone nettle compute CLI. Passing any
# argument also builds the fault-injected variant.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUB="$ROOT/harness/subproc"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

CC="${CC:-cc}"
# Ed25519 / X25519 live in libhogweed (GMP-backed), so link hogweed + nettle + gmp.
NET_CFLAGS=""; NET_LIBS="-lhogweed -lnettle -lgmp"
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists hogweed 2>/dev/null; then
  NET_CFLAGS="$(pkg-config --cflags hogweed)"
  NET_LIBS="$(pkg-config --libs hogweed)"
fi

[ -x "$OUT/diff_subproc" ] || $CC -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$OUT/diff_subproc"

$CC -g -O1 $NET_CFLAGS "$SUB/compute_nettle.c" -I"$SUB" $NET_LIBS -o "$OUT/compute_nettle"
echo "[build] compute_nettle -> $OUT/compute_nettle"

if [ -n "${1:-}" ]; then
  $CC -g -O1 -DCMF_DIFF_FAULT=1 $NET_CFLAGS "$SUB/compute_nettle.c" -I"$SUB" $NET_LIBS -o "$OUT/compute_nettle_fault"
  echo "[build] compute_nettle_fault -> $OUT/compute_nettle_fault"
fi
