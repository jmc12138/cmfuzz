#!/usr/bin/env bash
# Negative (mutation) tests: prove the metamorphic oracles actually FIRE when the
# invariant is broken. Each fault-injected harness must abort with the expected
# CMF_VIOLATION line. A framework that only ever prints "0 violations" is
# worthless unless we also show it catches real ones.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OQS="$ROOT/libs/liboqs"
TMP="$(mktemp -d)"
INC="-I$OQS/build/include"; LIB="$OQS/build/lib/liboqs.a"; EXTRA="-lcrypto -lpthread -ldl"
SAN="-fsanitize=address,undefined,fuzzer -g -O1"
pass=0; fail=0

SEED="$TMP/seed"; mkdir -p "$SEED"; head -c 64 /dev/urandom > "$SEED/s1"

check() {  # name  binary  expected_oracle
  local name="$1" bin="$2" want="$3"
  # seed with a >=8 byte input so the oracle path is reached; one crash suffices
  out="$("$bin" -runs=2000 "$SEED" 2>&1 || true)"
  if echo "$out" | grep -q "CMF_VIOLATION.*oracle=$want"; then
    echo "PASS  $name (fired $want)"; pass=$((pass+1))
  else
    echo "FAIL  $name (expected oracle=$want)"; echo "$out" | tail -3; fail=$((fail+1))
  fi
}

echo "[neg] building fault-injected harnesses..."
clang $SAN $INC -DCMF_KEM_ALG='"ML-KEM-768"' -DCMF_FAULT_MR1 \
  "$ROOT/harness/liboqs_kem_harness.c" "$LIB" $EXTRA -o "$TMP/kem_fault_mr1"
clang $SAN $INC -DCMF_SIG_ALG='"ML-DSA-65"' -DCMF_FAULT_MR3 \
  "$ROOT/harness/liboqs_sig_harness.c" "$LIB" $EXTRA -o "$TMP/sig_fault_mr3"

clang $SAN -DCMF_FAULT_TRAD=1 \
  "$ROOT/harness/trad_metamorphic_harness.c" -lcrypto -o "$TMP/trad_fault"

clang $SAN -DCMF_HPKE_KEM=0 -DCMF_FAULT_HPKE=1 \
  "$ROOT/harness/comp_hpke_harness.c" -lcrypto -o "$TMP/hpke_fault"

echo "[neg] running..."
check "KEM correctness (MR1) detects corrupted shared secret" "$TMP/kem_fault_mr1" "MR1_correctness"
check "SIG SUF (MR3) detects malleable-verify"                 "$TMP/sig_fault_mr3" "MR3_strong_unforgeability"
check "Traditional AEAD tamper-reject detects forged tag"     "$TMP/trad_fault" "tamper_reject"
check "L2 HPKE composition detects tampered encapsulated key" "$TMP/hpke_fault" "O5-upstream-tamper"

# Differential oracle self-test (only if the extra libs are built).
if [ -f "$ROOT/libs/cryptopp/libcryptopp.a" ] && \
   [ -f "$ROOT/libs/mbedtls/build/library/libmbedcrypto.a" ] && \
   [ -f "$ROOT/libs/libsodium/build/lib/libsodium.a" ]; then
  echo "[neg] building fault-injected differential harness..."
  CMF_DIFF_FAULT=1 bash "$ROOT/scripts/build_diff_harness.sh" "$TMP/diff_fault" >/dev/null 2>&1
  check "Differential (SHA-256) detects a divergent implementation" "$TMP/diff_fault" "DIFF_mismatch"
else
  echo "SKIP  differential self-test (extra libs not built; run scripts/build_diff_libs.sh)"
fi

echo "[neg] $pass passed, $fail failed"
rm -rf "$TMP"
[ "$fail" -eq 0 ]
