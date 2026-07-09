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
# L2 composition harness: HPKE-style KEM+KDF+AEAD (X25519 + ML-KEM-768 backends)
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  -DCMF_HPKE_KEM=0 "$ROOT/harness/comp_hpke_harness.c" -lcrypto \
  -o "$ROOT/build/harness/comp_hpke_x25519"
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  -DCMF_HPKE_KEM=1 -I"$ROOT/libs/liboqs/build/include" "$ROOT/harness/comp_hpke_harness.c" \
  "$ROOT/libs/liboqs/build/lib/liboqs.a" -lcrypto -o "$ROOT/build/harness/comp_hpke_mlkem"
# L2 traditional composition: Encrypt-then-MAC (AES-CBC+HMAC) + TLS1.3-style record layer
clang -fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1 \
  "$ROOT/harness/comp_trad_harness.c" -lcrypto -o "$ROOT/build/harness/comp_trad"
# Extra libraries + multi-library differential harness (optional; skipped if the
# extra libs failed to build so a minimal setup still succeeds).
if bash "$ROOT/scripts/build_diff_libs.sh"; then
  bash "$ROOT/scripts/build_diff_harness.sh" || echo "[build_all] diff harness skipped"
fi
echo "[build_all] done"
