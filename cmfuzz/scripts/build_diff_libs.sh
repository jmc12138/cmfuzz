#!/usr/bin/env bash
# Build extra crypto libraries as instrumented static libs so they can be linked
# into the multi-library differential harness (Cryptofuzz-style cross-checking).
# All built with clang + ASan + coverage (fuzzer-no-link) so the differential
# harness is coverage-guided through the library code, not just the harness.
set -uo pipefail
LIBS="$(cd "$(dirname "$0")/../libs" && pwd)"
export CC=clang CXX=clang++
IFLAGS="-fsanitize=address,fuzzer-no-link -g -O1 -fno-omit-frame-pointer"
JOBS="$(nproc)"

# Clone the differential library sources at pinned versions if absent. These
# are not vendored in git (like liboqs/SEAL) so a fresh checkout can rebuild the
# whole differential stack from scratch.
clone_pin() {  # url dir tag
  local url="$1" dir="$2" tag="$3"
  [ -d "$LIBS/$dir/.git" ] && return 0
  echo "[clone] $dir @ $tag"
  git clone --depth 1 --branch "$tag" --recurse-submodules --shallow-submodules \
    "$url" "$LIBS/$dir" 2>/dev/null \
    || git clone --depth 1 --recurse-submodules "$url" "$LIBS/$dir"
}
clone_pin https://github.com/jedisct1/libsodium.git libsodium 1.0.20
clone_pin https://github.com/Mbed-TLS/mbedtls.git    mbedtls   mbedtls-3.6.2
clone_pin https://github.com/weidai11/cryptopp.git   cryptopp  CRYPTOPP_8_9_0

echo "===== libsodium ====="
cd "$LIBS/libsodium"
if [ ! -f build/lib/libsodium.a ]; then
  ./autogen.sh -s >/dev/null 2>&1
  CFLAGS="$IFLAGS" ./configure --disable-shared --enable-static \
    --prefix="$LIBS/libsodium/build" >/tmp/sodium_conf.log 2>&1
  make -j"$JOBS" >/tmp/sodium_make.log 2>&1 && make install >/tmp/sodium_inst.log 2>&1
fi
ls -la "$LIBS/libsodium/build/lib/libsodium.a" 2>&1

echo "===== mbedtls ====="
cd "$LIBS/mbedtls"
if [ ! -f build/library/libmbedcrypto.a ]; then
  python3 -m pip install -q -r scripts/basic.requirements.txt 2>/dev/null || true
  cmake -S . -B build -G Ninja \
    -DCMAKE_C_COMPILER=clang -DCMAKE_C_FLAGS="$IFLAGS" \
    -DENABLE_TESTING=Off -DENABLE_PROGRAMS=Off >/tmp/mbed_conf.log 2>&1
  cmake --build build -j"$JOBS" >/tmp/mbed_make.log 2>&1
fi
ls -la "$LIBS/mbedtls/build/library/libmbedcrypto.a" 2>&1

echo "===== cryptopp ====="
cd "$LIBS/cryptopp"
if [ ! -f libcryptopp.a ]; then
  make -j"$JOBS" CXX=clang++ CXXFLAGS="$IFLAGS -DNDEBUG -std=c++17" libcryptopp.a \
    >/tmp/cryptopp_make.log 2>&1
fi
ls -la "$LIBS/cryptopp/libcryptopp.a" 2>&1

echo "===== done ====="
