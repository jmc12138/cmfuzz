#!/usr/bin/env bash
# Build the multi-library differential harness (OpenSSL + libsodium + Mbed-TLS +
# Crypto++). Pass CMF_DIFF_FAULT=1 to build the fault-injected self-test variant.
set -euo pipefail
R="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$R/build/harness/diff_multilib}"
FAULT=""; [ "${CMF_DIFF_FAULT:-0}" = "1" ] && FAULT="-DCMF_DIFF_FAULT"
mkdir -p "$(dirname "$OUT")"

clang++ -std=c++17 -g -O1 -fsanitize=address,fuzzer -fno-omit-frame-pointer $FAULT \
  -I"$R/libs/libsodium/build/include" \
  -I"$R/libs/mbedtls/include" \
  -I"$R/libs" \
  "$R/harness/diff_multilib_harness.cpp" \
  "$R/libs/cryptopp/libcryptopp.a" \
  "$R/libs/mbedtls/build/library/libmbedcrypto.a" \
  "$R/libs/libsodium/build/lib/libsodium.a" \
  -lcrypto \
  -o "$OUT"
echo "[diff] built $OUT"
