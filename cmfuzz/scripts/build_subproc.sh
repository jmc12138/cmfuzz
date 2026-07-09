#!/usr/bin/env bash
# Build the stage-2.1 subprocess differential stack
# (BoringSSL + aws-lc + wolfCrypt + Botan).
#
# Each extra library runs behind a standalone compute CLI driven by the runner
# (which links OpenSSL as the reference). BoringSSL/aws-lc must be isolated
# because they redefine OpenSSL symbols; wolfCrypt (wc_* API) and Botan (C++
# Botan:: namespace) use their own APIs and are kept behind a subprocess for
# uniformity. Targets:
#   - diff_subproc         : runner, links OpenSSL (reference), drives CLIs.
#   - compute_boringssl    : standalone CLI, links ONLY BoringSSL.
#   - compute_aws_lc       : standalone CLI, links ONLY aws-lc.
#   - compute_wolfssl      : standalone CLI, links ONLY wolfCrypt.
#   - compute_botan        : standalone CLI, links ONLY Botan (amalgamation).
#   - seq_boringssl        : BoringSSL EVP_AEAD L3 misuse harness (libFuzzer+ASan).
#   - seq_aws_lc           : aws-lc   EVP_AEAD L3 misuse harness (libFuzzer+ASan).
#   - seq_wolfssl          : wolfCrypt AES-GCM L3 misuse harness (libFuzzer+ASan).
#   - seq_botan            : Botan AEAD_Mode L3 misuse harness (libFuzzer+ASan).
#
# BoringSSL/aws-lc static libs contain C++ objects, so their consumers must be
# LINKED with clang++ even though the sources are C; wolfCrypt is pure C; Botan
# is C++. BoringSSL is required for this script; aws-lc (needs Go >= 1.20),
# wolfCrypt (needs autotools) and Botan (needs python3 + C++20) are optional and
# skipped if their build fails.
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

# wolfCrypt backend (optional: needs autotools). Native wc_* API — its compute
# CLI + L3 harness are pure C and link directly with clang (no C++ runtime).
if bash "$ROOT/scripts/build_wolfssl.sh" >/dev/null 2>&1; then
  WOLF_A="$(find "$ROOT/libs/wolfssl/src/.libs" -name libwolfssl.a 2>/dev/null | head -1)"
  WOLF_INC="$ROOT/libs/wolfssl"
  if [ -n "$WOLF_A" ]; then
    clang -g -O1 "$SUB/compute_wolfssl.c" -I"$SUB" -I"$WOLF_INC" "$WOLF_A" -lm -o "$OUT/compute_wolfssl"
    clang $SAN "$SUB/seq_wolfssl_harness.c" -I"$WOLF_INC" "$WOLF_A" -lm -o "$OUT/seq_wolfssl"
    built="$built + compute_wolfssl + seq_wolfssl"
  fi
else
  echo "[build_subproc] wolfCrypt skipped (build failed; needs autotools)" >&2
fi

# Botan backend (optional: C++, needs python3 + a C++20 compiler). Compiled
# against the single-file amalgamation produced by build_botan.sh.
if bash "$ROOT/scripts/build_botan.sh" >/dev/null 2>&1; then
  BOTAN_DIR="$ROOT/libs/botan"
  if [ -f "$BOTAN_DIR/botan_all.cpp" ]; then
    clang++ -std=c++20 -O1 -g -I"$BOTAN_DIR" -I"$SUB" \
      "$SUB/compute_botan.cpp" "$BOTAN_DIR/botan_all.cpp" -o "$OUT/compute_botan"
    clang++ $SAN -std=c++20 -I"$BOTAN_DIR" \
      "$SUB/seq_botan_harness.cpp" "$BOTAN_DIR/botan_all.cpp" -o "$OUT/seq_botan"
    built="$built + compute_botan + seq_botan"
  fi
else
  echo "[build_subproc] Botan skipped (build failed; needs python3 + C++20)" >&2
fi

echo "[build_subproc] built $built"
