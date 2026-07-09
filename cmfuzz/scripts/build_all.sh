#!/usr/bin/env bash
# One-shot: build target libraries, (re)generate specs, build all harnesses.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/scripts/build_liboqs.sh"
bash "$ROOT/scripts/build_seal.sh"
python3 "$ROOT/spec_gen/generate_specs.py" --liboqs "$ROOT/libs/liboqs" ${CMF_LLM:+--llm}
bash "$ROOT/scripts/build_harness.sh"
# SEAL FHE harness (built separately: C++ + SEAL include/lib paths)
S="$ROOT/libs/SEAL"
clang++ -std=c++17 -fsanitize=fuzzer -g -O1 -I"$S/native/src" -I"$S/build/native/src" \
  "$ROOT/harness/seal_fhe_harness.cpp" "$S/build/lib/"libseal-*.a -o "$ROOT/build/harness/fhe_seal_bfv"
# OpenSSL classic harness
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  "$ROOT/harness/openssl_classic_harness.c" -lcrypto -o "$ROOT/build/harness/classic_openssl"
# Traditional metamorphic harness (round-trip / tamper-reject / chunk-consistency)
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  "$ROOT/harness/trad_metamorphic_harness.c" -lcrypto -o "$ROOT/build/harness/trad_metamorphic"
# Extra libraries + multi-library differential harness (optional; skipped if the
# extra libs failed to build so a minimal setup still succeeds).
if bash "$ROOT/scripts/build_diff_libs.sh"; then
  bash "$ROOT/scripts/build_diff_harness.sh" || echo "[build_all] diff harness skipped"
fi
echo "[build_all] done"
