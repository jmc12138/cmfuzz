#!/usr/bin/env bash
# Build liboqs (static, Debug so ASan/UBSan give useful traces) into libs/liboqs/build.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OQS="$ROOT/libs/liboqs"
[ -d "$OQS" ] || git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "$OQS"
cmake -GNinja -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_BUILD_TYPE=Debug -DOQS_DIST_BUILD=ON -B "$OQS/build" -S "$OQS"
ninja -C "$OQS/build"
echo "[liboqs] built -> $OQS/build/lib/liboqs.a"
