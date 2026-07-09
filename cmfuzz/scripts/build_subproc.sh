#!/usr/bin/env bash
# Build the stage-2.1 subprocess differential stack (BoringSSL + aws-lc).
#
# BoringSSL / aws-lc redefine OpenSSL symbols, so they cannot share a process
# with the OpenSSL-linked reference. Instead:
#   - diff_subproc         : runner, links OpenSSL (reference), drives CLIs.
#   - compute_boringssl    : standalone CLI, links ONLY BoringSSL.
#   - compute_aws_lc       : standalone CLI, links ONLY aws-lc.
#   - seq_boringssl        : BoringSSL EVP_AEAD L3 misuse harness (libFuzzer+ASan).
#   - seq_aws_lc           : aws-lc   EVP_AEAD L3 misuse harness (libFuzzer+ASan).
#
# These static libs are built from C++ objects, so their consumers must be
# LINKED with clang++ (C++ runtime) even though the sources are C. BoringSSL is
# required for this script; aws-lc is optional (needs Go >= 1.20) and skipped if
# its build fails.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

bash "$ROOT/scripts/build_boringssl.sh" >/dev/null
BSSL_A="$(find "$ROOT/libs/boringssl/build" -name libcrypto.a | head -1)"
BSSL_INC="$ROOT/libs/boringssl/include"
[ -n "$BSSL_A" ] || { echo "[build_subproc] BoringSSL libcrypto.a not found" >&2; exit 1; }

SUB="$ROOT/harness/subproc"
SAN="-fsanitize=address,fuzzer -g -O1"

# Differential runner (OpenSSL reference, in-process).
clang -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$OUT/diff_subproc"

# BoringSSL compute CLI (compile C object with clang, link with clang++).
clang -g -O1 -c "$SUB/compute_boringssl.c" -I"$SUB" -I"$BSSL_INC" -o "$OUT/compute_boringssl.o"
clang++ -g -O1 "$OUT/compute_boringssl.o" "$BSSL_A" -lpthread -o "$OUT/compute_boringssl" 2>/dev/null

# BoringSSL L3 EVP_AEAD misuse harness.
clang $SAN -c "$SUB/seq_boringssl_harness.c" -I"$BSSL_INC" -o "$OUT/seq_boringssl.o"
clang++ $SAN "$OUT/seq_boringssl.o" "$BSSL_A" -lpthread -o "$OUT/seq_boringssl" 2>/dev/null

built="diff_subproc + compute_boringssl + seq_boringssl"

# aws-lc backend (optional: needs Go >= 1.20). Same EVP_AEAD API as BoringSSL.
if bash "$ROOT/scripts/build_aws_lc.sh" >/dev/null 2>&1; then
  AWSLC_A="$(find "$ROOT/libs/aws-lc/build" -name libcrypto.a 2>/dev/null | head -1)"
  AWSLC_INC="$ROOT/libs/aws-lc/include"
  if [ -n "$AWSLC_A" ]; then
    clang -g -O1 -c "$SUB/compute_aws_lc.c" -I"$SUB" -I"$AWSLC_INC" -o "$OUT/compute_aws_lc.o"
    clang++ -g -O1 "$OUT/compute_aws_lc.o" "$AWSLC_A" -lpthread -o "$OUT/compute_aws_lc" 2>/dev/null
    clang $SAN -c "$SUB/seq_aws_lc_harness.c" -I"$AWSLC_INC" -o "$OUT/seq_aws_lc.o"
    clang++ $SAN "$OUT/seq_aws_lc.o" "$AWSLC_A" -lpthread -o "$OUT/seq_aws_lc" 2>/dev/null
    built="$built + compute_aws_lc + seq_aws_lc"
  fi
else
  echo "[build_subproc] aws-lc skipped (build failed; needs Go >= 1.20)" >&2
fi

echo "[build_subproc] built $built"
