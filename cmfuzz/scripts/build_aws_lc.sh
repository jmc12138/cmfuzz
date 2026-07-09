#!/usr/bin/env bash
# Build aws-lc as a static libcrypto.a for the subprocess differential CLI.
# aws-lc is AWS's fork of BoringSSL: it keeps BoringSSL's one-shot EVP_AEAD API
# and likewise redefines OpenSSL symbols, so (like BoringSSL) it can NOT share a
# process with OpenSSL — its compute CLI is standalone and the differential
# runner drives it as a subprocess (see harness/subproc/). Needs cmake+ninja+Go.
set -uo pipefail
# aws-lc's cmake requires Go >= 1.20; Ubuntu 22.04's apt golang-go is 1.18.1, so
# prefer a manually installed Go under /usr/local/go if present.
[ -x /usr/local/go/bin/go ] && export PATH="/usr/local/go/bin:$PATH"
LIBS="$(cd "$(dirname "$0")/../libs" && pwd)"
AWSLC="$LIBS/aws-lc"
if [ ! -d "$AWSLC/.git" ]; then
  echo "[clone] aws-lc"
  git clone --depth 1 https://github.com/aws/aws-lc.git "$AWSLC"
fi
if [ ! -f "$AWSLC/build/crypto/libcrypto.a" ] && [ ! -f "$AWSLC/build/libcrypto.a" ]; then
  cmake -S "$AWSLC" -B "$AWSLC/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF -DBUILD_LIBSSL=OFF \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ >/tmp/awslc_conf.log 2>&1
  ninja -C "$AWSLC/build" crypto >/tmp/awslc_make.log 2>&1
fi
# Report the static lib location (layout differs across versions).
find "$AWSLC/build" -name libcrypto.a 2>/dev/null | head -1
