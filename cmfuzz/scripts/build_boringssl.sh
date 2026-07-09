#!/usr/bin/env bash
# Build BoringSSL as a static libcrypto.a for the subprocess differential CLI.
# BoringSSL redefines OpenSSL symbols (SHA256, EVP_*, ...), so it can NOT be
# linked into the same process as OpenSSL — its compute CLI is a standalone
# binary that links ONLY BoringSSL, and the differential runner drives it as a
# subprocess (see harness/subproc/). Needs cmake + ninja + Go.
set -uo pipefail
# Prefer a manually installed Go under /usr/local/go if present (BoringSSL builds
# with the apt 1.18 too, but the Docker image ships Go 1.22 there for aws-lc).
[ -x /usr/local/go/bin/go ] && export PATH="/usr/local/go/bin:$PATH"
LIBS="$(cd "$(dirname "$0")/../libs" && pwd)"
BSSL="$LIBS/boringssl"
if [ ! -d "$BSSL/.git" ]; then
  echo "[clone] boringssl"
  git clone --depth 1 https://github.com/google/boringssl.git "$BSSL"
fi
if [ ! -f "$BSSL/build/libcrypto.a" ] && [ ! -f "$BSSL/build/crypto/libcrypto.a" ]; then
  cmake -S "$BSSL" -B "$BSSL/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ >/tmp/bssl_conf.log 2>&1
  ninja -C "$BSSL/build" crypto >/tmp/bssl_make.log 2>&1
fi
# Report the static lib location (layout differs across BoringSSL versions).
find "$BSSL/build" -name libcrypto.a 2>/dev/null | head -1
