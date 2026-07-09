#!/usr/bin/env bash
# Build the stage-2.1 subprocess differential stack (BoringSSL backend).
#
# BoringSSL redefines OpenSSL symbols, so it cannot share a process with the
# OpenSSL-linked reference. Instead:
#   - diff_subproc         : runner, links OpenSSL (reference), drives CLIs.
#   - compute_boringssl    : standalone CLI, links ONLY BoringSSL.
#   - seq_boringssl        : BoringSSL EVP_AEAD L3 misuse harness (libFuzzer+ASan).
#
# BoringSSL's static lib is built from C++ objects, so its consumers must be
# LINKED with clang++ (C++ runtime) even though the sources are C.
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

echo "[build_subproc] built diff_subproc + compute_boringssl + seq_boringssl"
