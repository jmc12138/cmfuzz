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

clang $SAN -DCMF_FAULT_ETM=1 \
  "$ROOT/harness/comp_trad_harness.c" -lcrypto -o "$TMP/etm_fault"
clang $SAN -DCMF_FAULT_REC=1 \
  "$ROOT/harness/comp_trad_harness.c" -lcrypto -o "$TMP/rec_fault"

clang $SAN -DCMF_AK_PQC=0 -DCMF_FAULT_AK=1 \
  "$ROOT/harness/comp_authkem_harness.c" -lcrypto -o "$TMP/ak_fault"
clang $SAN -DCMF_FAULT_KDF=1 \
  "$ROOT/harness/comp_kdfchain_harness.c" -lcrypto -o "$TMP/kdf_fault"

clang $SAN -DCMF_FAULT_NONCE=1 \
  "$ROOT/harness/seq_aead_harness.c" -lcrypto -o "$TMP/nonce_fault"
clang $SAN -DCMF_FAULT_RELEASE=1 \
  "$ROOT/harness/seq_aead_harness.c" -lcrypto -o "$TMP/release_fault"
clang $SAN -DCMF_FAULT_KREUSE=1 \
  "$ROOT/harness/seq_ecdsa_harness.c" -lcrypto -o "$TMP/kreuse_fault"
clang $SAN -I"$ROOT/libs/liboqs/build/include" -DCMF_FAULT_KEMSWAP=1 \
  "$ROOT/harness/seq_pqc_harness.c" "$ROOT/libs/liboqs/build/lib/liboqs.a" -lcrypto -o "$TMP/kemswap_fault"
clang $SAN -DCMF_FAULT_IV=1 \
  "$ROOT/harness/seq_evp_harness.c" -lcrypto -o "$TMP/iv_fault"
clang $SAN -DCMF_FAULT_UAF=1 \
  "$ROOT/harness/seq_evp_harness.c" -lcrypto -o "$TMP/uaf_fault"

echo "[neg] running..."
check "KEM correctness (MR1) detects corrupted shared secret" "$TMP/kem_fault_mr1" "MR1_correctness"
check "SIG SUF (MR3) detects malleable-verify"                 "$TMP/sig_fault_mr3" "MR3_strong_unforgeability"
check "Traditional AEAD tamper-reject detects forged tag"     "$TMP/trad_fault" "tamper_reject"
check "L2 HPKE composition detects tampered encapsulated key" "$TMP/hpke_fault" "O5-upstream-tamper"
check "L2 EtM detects tampered ciphertext/tag"                "$TMP/etm_fault" "O5-ciphertext-integrity"
check "L2 TLS1.3 record detects wrong sequence number"        "$TMP/rec_fault" "O5-seq-binding"
check "L2 AuthKEM detects unbound (swappable) encapsulation"  "$TMP/ak_fault" "O5-transcript-binding"
check "L2 KDF chain detects collapsed (non-advancing) keys"   "$TMP/kdf_fault" "O5-key-separation"
check "L3 AEAD detects catastrophic nonce reuse"              "$TMP/nonce_fault" "O6-nonce-uniqueness"
check "L3 AEAD detects release of unverified plaintext"       "$TMP/release_fault" "O6-release-before-verify"
check "L3 ECDSA detects per-signature nonce (k) reuse"        "$TMP/kreuse_fault" "O6-ecdsa-k-uniqueness"
check "L3 PQC KEM detects wrong-key false agreement"          "$TMP/kemswap_fault" "O6-kem-key-confusion"
check "L3 CBC detects predictable/reused IV"                  "$TMP/iv_fault" "O6-iv-unpredictability"
check "L3 EVP detects context use-after-free"                 "$TMP/uaf_fault" "O6-ctx-use-after-free"

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

# Stage 2.1 subprocess differential + BoringSSL L3 self-tests (only if BoringSSL built).
BSSL_A="$(find "$ROOT/libs/boringssl/build" -name libcrypto.a 2>/dev/null | head -1)"
if [ -n "$BSSL_A" ]; then
  BINC="-I$ROOT/libs/boringssl/include"; BSAN="-fsanitize=address,fuzzer -g -O1"
  SUB="$ROOT/harness/subproc"
  echo "[neg] building BoringSSL fault-injected L3 harnesses..."
  clang $BSAN $BINC -DCMF_FAULT_NONCE=1 -c "$SUB/seq_boringssl_harness.c" -o "$TMP/sbn.o"
  clang++ $BSAN "$TMP/sbn.o" "$BSSL_A" -lpthread -o "$TMP/bssl_nonce" 2>/dev/null
  clang $BSAN $BINC -DCMF_FAULT_RELEASE=1 -c "$SUB/seq_boringssl_harness.c" -o "$TMP/sbr.o"
  clang++ $BSAN "$TMP/sbr.o" "$BSSL_A" -lpthread -o "$TMP/bssl_release" 2>/dev/null
  check "L3 BoringSSL EVP_AEAD detects nonce reuse"            "$TMP/bssl_nonce" "O6-nonce-uniqueness"
  check "L3 BoringSSL EVP_AEAD detects release-before-verify"  "$TMP/bssl_release" "O6-release-before-verify"

  echo "[neg] building subprocess differential self-test..."
  clang -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$TMP/diff_subproc"
  clang -g -O1 -DCMF_DIFF_FAULT=1 -c "$SUB/compute_boringssl.c" $BINC -I"$SUB" -o "$TMP/cbf.o"
  clang++ -g -O1 "$TMP/cbf.o" "$BSSL_A" -lpthread -o "$TMP/compute_bssl_fault" 2>/dev/null
  "$TMP/diff_subproc" 200 12345 boringssl_fault="$TMP/compute_bssl_fault" > "$TMP/subout.txt" 2>&1 || true
  cat "$TMP/subout.txt" >&2
  if grep -q "oracle=DIFF_mismatch" "$TMP/subout.txt"; then
    echo "PASS  Subprocess differential detects divergent BoringSSL backend (DIFF_mismatch)"; pass=$((pass+1))
  else
    echo "FAIL  Subprocess differential (expected DIFF_mismatch)"; fail=$((fail+1))
  fi
else
  echo "SKIP  BoringSSL subprocess self-tests (BoringSSL not built; run scripts/build_boringssl.sh — needs Go)"
fi

# aws-lc subprocess differential + L3 self-tests (only if aws-lc built; needs Go >= 1.20).
AWSLC_A="$(find "$ROOT/libs/aws-lc/build" -name libcrypto.a 2>/dev/null | head -1)"
if [ -n "$AWSLC_A" ]; then
  AINC="-I$ROOT/libs/aws-lc/include"; ASAN="-fsanitize=address,fuzzer -g -O1"
  SUB="$ROOT/harness/subproc"
  echo "[neg] building aws-lc fault-injected L3 harnesses..."
  clang $ASAN $AINC -DCMF_FAULT_NONCE=1 -c "$SUB/seq_aws_lc_harness.c" -o "$TMP/san.o"
  clang++ $ASAN "$TMP/san.o" "$AWSLC_A" -lpthread -o "$TMP/awslc_nonce" 2>/dev/null
  clang $ASAN $AINC -DCMF_FAULT_RELEASE=1 -c "$SUB/seq_aws_lc_harness.c" -o "$TMP/sar.o"
  clang++ $ASAN "$TMP/sar.o" "$AWSLC_A" -lpthread -o "$TMP/awslc_release" 2>/dev/null
  check "L3 aws-lc EVP_AEAD detects nonce reuse"              "$TMP/awslc_nonce" "O6-nonce-uniqueness"
  check "L3 aws-lc EVP_AEAD detects release-before-verify"    "$TMP/awslc_release" "O6-release-before-verify"

  echo "[neg] building aws-lc subprocess differential self-test..."
  [ -x "$TMP/diff_subproc" ] || clang -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$TMP/diff_subproc"
  clang -g -O1 -DCMF_DIFF_FAULT=1 -c "$SUB/compute_aws_lc.c" $AINC -I"$SUB" -o "$TMP/caf.o"
  clang++ -g -O1 "$TMP/caf.o" "$AWSLC_A" -lpthread -o "$TMP/compute_awslc_fault" 2>/dev/null
  "$TMP/diff_subproc" 200 12345 aws-lc_fault="$TMP/compute_awslc_fault" > "$TMP/subout_awslc.txt" 2>&1 || true
  cat "$TMP/subout_awslc.txt" >&2
  if grep -q "oracle=DIFF_mismatch" "$TMP/subout_awslc.txt"; then
    echo "PASS  Subprocess differential detects divergent aws-lc backend (DIFF_mismatch)"; pass=$((pass+1))
  else
    echo "FAIL  Subprocess differential aws-lc (expected DIFF_mismatch)"; fail=$((fail+1))
  fi
else
  echo "SKIP  aws-lc subprocess self-tests (aws-lc not built; run scripts/build_aws_lc.sh — needs Go >= 1.20)"
fi

echo "[neg] $pass passed, $fail failed"
rm -rf "$TMP"
[ "$fail" -eq 0 ]
