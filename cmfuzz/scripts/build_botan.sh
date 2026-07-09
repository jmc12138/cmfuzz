#!/usr/bin/env bash
# Prepare Botan (C++) for the subprocess differential CLI, as a single-file
# amalgamation (botan_all.{h,cpp}) built with only the modules we need. Botan is
# C++ with its own Botan:: namespace + AEAD_Mode/HashFunction/MAC state machine,
# so it gets its own compute CLI + L3 misuse harness (per PLAN 2.1) and is kept
# behind a subprocess for uniformity. Needs python3 + a C++20 compiler.
set -uo pipefail
LIBS="$(cd "$(dirname "$0")/../libs" && pwd)"
BOTAN="$LIBS/botan"
BOTAN_TAG="3.8.1"
if [ ! -d "$BOTAN/.git" ]; then
  echo "[clone] botan $BOTAN_TAG"
  git clone --depth 1 --branch "$BOTAN_TAG" https://github.com/randombit/botan.git "$BOTAN"
fi
if [ ! -f "$BOTAN/botan_all.cpp" ]; then
  ( cd "$BOTAN" && python3 configure.py --cc=clang --amalgamation \
      --minimized-build --without-documentation \
      --enable-modules=sha2_32,sha2_64,sha3,shake,hmac,gcm,aes,chacha20poly1305,hkdf,pbkdf2 \
      >/tmp/botan_conf.log 2>&1 )
fi
# The amalgamation is what consumers compile against (see build_subproc.sh).
[ -f "$BOTAN/botan_all.cpp" ] && echo "$BOTAN/botan_all.cpp"
