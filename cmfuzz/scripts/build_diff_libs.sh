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
