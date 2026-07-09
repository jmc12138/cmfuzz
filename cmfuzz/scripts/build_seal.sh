#!/usr/bin/env bash
# Build Microsoft SEAL (static, Release) into libs/SEAL/build for the FHE harness.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEAL="$ROOT/libs/SEAL"
[ -d "$SEAL" ] || git clone --depth 1 https://github.com/microsoft/SEAL.git "$SEAL"
cmake -S "$SEAL" -B "$SEAL/build" -DSEAL_BUILD_DEPS=ON -DCMAKE_BUILD_TYPE=Release \
      -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
cmake --build "$SEAL/build" -j"$(nproc)"
echo "[SEAL] built -> $SEAL/build/lib/"
