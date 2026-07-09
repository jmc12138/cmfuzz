#!/usr/bin/env bash
# Build wolfSSL/wolfCrypt as a static libwolfssl.a for the subprocess
# differential CLI. wolfCrypt exposes its own native API (wc_Sha256, wc_AesGcm*,
# wc_ChaCha20Poly1305_*, ...) with a distinct state machine, so it gets its own
# compute CLI + L3 misuse harness (per PLAN 2.1). Built without the OpenSSL
# compat layer, so it is kept behind a subprocess for uniformity with the other
# differential backends. Needs autoconf/automake/libtool (autotools build).
set -uo pipefail
LIBS="$(cd "$(dirname "$0")/../libs" && pwd)"
WOLF="$LIBS/wolfssl"
if [ ! -d "$WOLF/.git" ]; then
  echo "[clone] wolfssl"
  git clone --depth 1 https://github.com/wolfSSL/wolfssl.git "$WOLF"
fi
LIB="$(find "$WOLF/src/.libs" -name libwolfssl.a 2>/dev/null | head -1)"
if [ -z "$LIB" ]; then
  ( cd "$WOLF" && ./autogen.sh >/tmp/wolf_autogen.log 2>&1 \
    && ./configure --enable-static --disable-shared \
         --enable-aesgcm --enable-chacha --enable-poly1305 \
         --enable-sha512 --enable-sha3 --enable-hmac --enable-hkdf --enable-pwdbased \
         --enable-curve25519 --enable-ed25519 --enable-ecc >/tmp/wolf_conf.log 2>&1 \
    && make -j"$(nproc)" >/tmp/wolf_make.log 2>&1 )
fi
find "$WOLF/src/.libs" -name libwolfssl.a 2>/dev/null | head -1
