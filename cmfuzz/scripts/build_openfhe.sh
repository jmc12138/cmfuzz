#!/usr/bin/env bash
# Build OpenFHE (static, Release) into libs/openfhe/build for the stage-2.5 FHE
# cross-library differential (OpenFHE vs Microsoft SEAL, BFV scheme).
#
# Only the static libraries are built (no unittests/benchmarks/examples) to keep
# the build tractable. OpenFHE is gitignored and cloned on demand, exactly like
# liboqs / SEAL / PQClean.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OFHE="$ROOT/libs/openfhe"
REF="${OPENFHE_REF:-v1.2.3}"

[ -d "$OFHE" ] || git clone --depth 1 --branch "$REF" \
    https://github.com/openfheorg/openfhe-development.git "$OFHE"

# CMAKE_POLICY_VERSION_MINIMUM lets CMake >= 4 configure projects whose
# cmake_minimum_required predates 3.5.
cmake -S "$OFHE" -B "$OFHE/build" \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_UNITTESTS=OFF \
      -DBUILD_BENCHMARKS=OFF \
      -DBUILD_EXAMPLES=OFF \
      -DBUILD_STATIC=ON \
      -DBUILD_SHARED=OFF \
      -DCMAKE_INSTALL_PREFIX="$OFHE/install" \
      -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build "$OFHE/build" -j"$(nproc)" --target OPENFHEcore_static OPENFHEpke_static OPENFHEbinfhe_static
# Install headers into a clean prefix so the harness gets a tidy include/ layout
# (OpenFHE's in-tree headers are scattered across src/{core,pke,binfhe}/include).
# The static .a archives stay in build/lib (OpenFHE hardcodes an absolute lib
# install dir that needs root); the harness links them from there directly.
cmake --install "$OFHE/build" || true
echo "[openfhe] built -> $OFHE/build/lib/ ; headers -> $OFHE/install/include/openfhe/"
