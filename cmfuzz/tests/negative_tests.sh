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

# wolfCrypt subprocess differential + L3 self-tests (only if wolfCrypt built; needs autotools).
WOLF_A="$(find "$ROOT/libs/wolfssl/src/.libs" -name libwolfssl.a 2>/dev/null | head -1)"
if [ -n "$WOLF_A" ]; then
  WINC="-I$ROOT/libs/wolfssl"; WSAN="-fsanitize=address,fuzzer -g -O1"
  SUB="$ROOT/harness/subproc"
  echo "[neg] building wolfCrypt fault-injected L3 harnesses..."
  clang $WSAN $WINC -DCMF_FAULT_NONCE=1 "$SUB/seq_wolfssl_harness.c" "$WOLF_A" -lm -o "$TMP/wolf_nonce" 2>/dev/null
  clang $WSAN $WINC -DCMF_FAULT_RELEASE=1 "$SUB/seq_wolfssl_harness.c" "$WOLF_A" -lm -o "$TMP/wolf_release" 2>/dev/null
  check "L3 wolfCrypt AES-GCM detects nonce reuse"             "$TMP/wolf_nonce" "O6-nonce-uniqueness"
  check "L3 wolfCrypt AES-GCM detects release-before-verify"   "$TMP/wolf_release" "O6-release-before-verify"

  echo "[neg] building wolfCrypt subprocess differential self-test..."
  [ -x "$TMP/diff_subproc" ] || clang -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$TMP/diff_subproc"
  clang -g -O1 -DCMF_DIFF_FAULT=1 "$SUB/compute_wolfssl.c" $WINC -I"$SUB" "$WOLF_A" -lm -o "$TMP/compute_wolf_fault" 2>/dev/null
  "$TMP/diff_subproc" 200 12345 wolfcrypt_fault="$TMP/compute_wolf_fault" > "$TMP/subout_wolf.txt" 2>&1 || true
  cat "$TMP/subout_wolf.txt" >&2
  if grep -q "oracle=DIFF_mismatch" "$TMP/subout_wolf.txt"; then
    echo "PASS  Subprocess differential detects divergent wolfCrypt backend (DIFF_mismatch)"; pass=$((pass+1))
  else
    echo "FAIL  Subprocess differential wolfCrypt (expected DIFF_mismatch)"; fail=$((fail+1))
  fi
else
  echo "SKIP  wolfCrypt subprocess self-tests (wolfCrypt not built; run scripts/build_wolfssl.sh — needs autotools)"
fi

# Botan subprocess differential + L3 self-tests (only if Botan amalgamation present; needs python3 + C++20).
BOTAN_DIR="$ROOT/libs/botan"
if [ -f "$BOTAN_DIR/botan_all.cpp" ]; then
  BSAN="-fsanitize=address,fuzzer -g -O1 -std=c++20"
  SUB="$ROOT/harness/subproc"
  echo "[neg] building Botan fault-injected L3 harnesses (compiles amalgamation)..."
  clang++ $BSAN -DCMF_FAULT_NONCE=1 -I"$BOTAN_DIR" "$SUB/seq_botan_harness.cpp" "$BOTAN_DIR/botan_all.cpp" -o "$TMP/botan_nonce" 2>/dev/null
  clang++ $BSAN -DCMF_FAULT_RELEASE=1 -I"$BOTAN_DIR" "$SUB/seq_botan_harness.cpp" "$BOTAN_DIR/botan_all.cpp" -o "$TMP/botan_release" 2>/dev/null
  check "L3 Botan AEAD detects nonce reuse"                 "$TMP/botan_nonce" "O6-nonce-uniqueness"
  check "L3 Botan AEAD detects release-before-verify"       "$TMP/botan_release" "O6-release-before-verify"

  echo "[neg] building Botan subprocess differential self-test..."
  [ -x "$TMP/diff_subproc" ] || clang -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$TMP/diff_subproc"
  clang++ -std=c++20 -O1 -g -DCMF_DIFF_FAULT=1 -I"$BOTAN_DIR" -I"$SUB" "$SUB/compute_botan.cpp" "$BOTAN_DIR/botan_all.cpp" -o "$TMP/compute_botan_fault" 2>/dev/null
  "$TMP/diff_subproc" 200 12345 botan_fault="$TMP/compute_botan_fault" > "$TMP/subout_botan.txt" 2>&1 || true
  cat "$TMP/subout_botan.txt" >&2
  if grep -q "oracle=DIFF_mismatch" "$TMP/subout_botan.txt"; then
    echo "PASS  Subprocess differential detects divergent Botan backend (DIFF_mismatch)"; pass=$((pass+1))
  else
    echo "FAIL  Subprocess differential Botan (expected DIFF_mismatch)"; fail=$((fail+1))
  fi
else
  echo "SKIP  Botan subprocess self-tests (Botan not built; run scripts/build_botan.sh — needs python3 + C++20)"
fi

# Stage 2.3 PQC cross-library differential self-test (liboqs vs PQClean; only if
# the PQClean archive is built).
PQC_A="$ROOT/libs/pqclean/build/libpqclean.a"
if [ -f "$PQC_A" ]; then
  echo "[neg] building fault-injected PQC differential (liboqs vs PQClean)..."
  clang -fsanitize=address,undefined -fno-sanitize-recover=undefined -g -O1 \
    -DCMF_PQC_FAULT=1 $INC "$ROOT/harness/pqc_diff_harness.c" \
    "$LIB" "$PQC_A" $EXTRA -o "$TMP/pqc_diff_fault" 2>/dev/null
  "$TMP/pqc_diff_fault" 50 12345 > "$TMP/pqcout.txt" 2>&1 || true
  cat "$TMP/pqcout.txt" >&2
  if grep -q "oracle=O1_kem_interop\|oracle=O1_sig_verify_interop" "$TMP/pqcout.txt"; then
    echo "PASS  PQC differential detects liboqs<->PQClean divergence (O1_*_interop)"; pass=$((pass+1))
  else
    echo "FAIL  PQC differential (expected O1_kem_interop / O1_sig_verify_interop)"; fail=$((fail+1))
  fi
else
  echo "SKIP  PQC differential self-test (PQClean not built; run scripts/build_pqclean.sh)"
fi

# Stage 2.3 PQC deterministic NIST-KAT byte-exact cross-check self-test (liboqs
# vs PQClean under a shared AES-256-CTR-DRBG; only if the PQClean archive built).
if [ -f "$PQC_A" ]; then
  echo "[neg] building fault-injected PQC KAT cross-check (liboqs vs PQClean)..."
  bash "$ROOT/scripts/build_pqc_kat.sh" fault >/dev/null 2>&1
  "$ROOT/build/harness/pqc_kat_fault" 5 > "$TMP/pqckat.txt" 2>&1 || true
  cat "$TMP/pqckat.txt" >&2
  if grep -q "oracle=O1_kat_bytes" "$TMP/pqckat.txt"; then
    echo "PASS  PQC KAT detects liboqs<->PQClean byte divergence (O1_kat_bytes)"; pass=$((pass+1))
  else
    echo "FAIL  PQC KAT (expected O1_kat_bytes)"; fail=$((fail+1))
  fi
  # Restore the clean (non-fault) binary so later stages / campaigns use it.
  bash "$ROOT/scripts/build_pqc_kat.sh" >/dev/null 2>&1 || true
else
  echo "SKIP  PQC KAT self-test (PQClean not built; run scripts/build_pqclean.sh)"
fi

# Stage 2.4 cross-language differential self-test (Go crypto vs OpenSSL; only if
# Go is available).
if command -v go >/dev/null 2>&1; then
  echo "[neg] building fault-injected Go cross-language backend..."
  [ -x "$TMP/diff_subproc" ] || clang -g -O1 "$ROOT/harness/subproc/diff_subproc_runner.c" -I"$ROOT/harness/subproc" -lcrypto -o "$TMP/diff_subproc"
  ( cd "$ROOT/harness/gobridge" && GOFLAGS=-mod=mod go build -ldflags "-X main.faultMode=1" -o "$TMP/compute_go_fault" . ) 2>/dev/null
  "$TMP/diff_subproc" 200 12345 go_fault="$TMP/compute_go_fault" > "$TMP/goout.txt" 2>&1 || true
  cat "$TMP/goout.txt" >&2
  if grep -q "oracle=DIFF_mismatch" "$TMP/goout.txt"; then
    echo "PASS  Cross-language differential detects divergent Go backend (DIFF_mismatch)"; pass=$((pass+1))
  else
    echo "FAIL  Cross-language differential Go (expected DIFF_mismatch)"; fail=$((fail+1))
  fi
else
  echo "SKIP  Go cross-language self-test (Go not installed)"
fi

# Stage 2.4 cross-language differential self-test (RustCrypto vs OpenSSL; only if
# cargo is available).
if command -v cargo >/dev/null 2>&1; then
  echo "[neg] building fault-injected Rust cross-language backend..."
  [ -x "$TMP/diff_subproc" ] || clang -g -O1 "$ROOT/harness/subproc/diff_subproc_runner.c" -I"$ROOT/harness/subproc" -lcrypto -o "$TMP/diff_subproc"
  ( cd "$ROOT/harness/rustbridge" && cargo build --release --features fault ) >/dev/null 2>&1
  cp "$ROOT/harness/rustbridge/target/release/compute_rust" "$TMP/compute_rust_fault"
  "$TMP/diff_subproc" 200 12345 rust_fault="$TMP/compute_rust_fault" > "$TMP/rustout.txt" 2>&1 || true
  cat "$TMP/rustout.txt" >&2
  if grep -q "oracle=DIFF_mismatch" "$TMP/rustout.txt"; then
    echo "PASS  Cross-language differential detects divergent Rust backend (DIFF_mismatch)"; pass=$((pass+1))
  else
    echo "FAIL  Cross-language differential Rust (expected DIFF_mismatch)"; fail=$((fail+1))
  fi
  # Rebuild the clean (non-fault) backend so a later plain build isn't left with
  # the fault-injected artifact in target/release.
  ( cd "$ROOT/harness/rustbridge" && cargo build --release ) >/dev/null 2>&1 || true
else
  echo "SKIP  Rust cross-language self-test (cargo not installed)"
fi

# Stage 3 ecosystem: PyCryptodome cross-language differential self-test (Python,
# independent implementation vs OpenSSL). Only if python3 + pycryptodome present.
if command -v python3 >/dev/null 2>&1 && python3 -c "import Crypto" >/dev/null 2>&1; then
  echo "[neg] building fault-injected PyCryptodome cross-language backend..."
  [ -x "$TMP/diff_subproc" ] || cc -g -O1 "$ROOT/harness/subproc/diff_subproc_runner.c" -I"$ROOT/harness/subproc" -lcrypto -o "$TMP/diff_subproc"
  cat > "$TMP/compute_py_fault" <<EOF
#!/usr/bin/env bash
exec env CMF_PY_FAULT=1 python3 "$ROOT/harness/subproc/compute_pycryptodome.py" "\$@"
EOF
  chmod +x "$TMP/compute_py_fault"
  "$TMP/diff_subproc" 200 12345 pycryptodome_fault="$TMP/compute_py_fault" > "$TMP/pyout.txt" 2>&1 || true
  cat "$TMP/pyout.txt" >&2
  if grep -q "oracle=DIFF_mismatch" "$TMP/pyout.txt"; then
    echo "PASS  Cross-language differential detects divergent PyCryptodome backend (DIFF_mismatch)"; pass=$((pass+1))
  else
    echo "FAIL  Cross-language differential PyCryptodome (expected DIFF_mismatch)"; fail=$((fail+1))
  fi
else
  echo "SKIP  PyCryptodome cross-language self-test (python3/pycryptodome not installed)"
fi

# Stage 3 ecosystem: libgcrypt (GnuPG) + nettle (GnuTLS) cross-library
# differential self-tests. Each fault variant (CMF_DIFF_FAULT) flips a byte; the
# runner must report DIFF_mismatch. Only run if the dev headers are present.
[ -x "$TMP/diff_subproc" ] || cc -g -O1 "$ROOT/harness/subproc/diff_subproc_runner.c" -I"$ROOT/harness/subproc" -lcrypto -o "$TMP/diff_subproc" 2>/dev/null || true
if [ -f /usr/include/gcrypt.h ]; then
  echo "[neg] building fault-injected libgcrypt backend..."
  GCR_LIBS="$(command -v libgcrypt-config >/dev/null 2>&1 && libgcrypt-config --libs || echo '-lgcrypt -lgpg-error')"
  cc -g -O1 -DCMF_DIFF_FAULT=1 "$ROOT/harness/subproc/compute_libgcrypt.c" -I"$ROOT/harness/subproc" $GCR_LIBS -o "$TMP/compute_libgcrypt_fault"
  "$TMP/diff_subproc" 200 12345 libgcrypt_fault="$TMP/compute_libgcrypt_fault" > "$TMP/gcrout.txt" 2>&1 || true
  cat "$TMP/gcrout.txt" >&2
  if grep -q "oracle=DIFF_mismatch" "$TMP/gcrout.txt"; then
    echo "PASS  Cross-library differential detects divergent libgcrypt backend (DIFF_mismatch)"; pass=$((pass+1))
  else
    echo "FAIL  Cross-library differential libgcrypt (expected DIFF_mismatch)"; fail=$((fail+1))
  fi
else
  echo "SKIP  libgcrypt cross-library self-test (libgcrypt20-dev not installed)"
fi
if [ -f /usr/include/nettle/sha2.h ]; then
  echo "[neg] building fault-injected nettle backend..."
  # Append -lnettle: some distros' hogweed.pc omits it (nettle is a private
  # requirement) yet compute_nettle.c references nettle_* symbols directly.
  NET_LIBS="$(pkg-config --libs hogweed 2>/dev/null && echo -lnettle -lgmp || echo '-lhogweed -lnettle -lgmp')"
  cc -g -O1 -DCMF_DIFF_FAULT=1 "$ROOT/harness/subproc/compute_nettle.c" -I"$ROOT/harness/subproc" $NET_LIBS -o "$TMP/compute_nettle_fault"
  "$TMP/diff_subproc" 200 12345 nettle_fault="$TMP/compute_nettle_fault" > "$TMP/netout.txt" 2>&1 || true
  cat "$TMP/netout.txt" >&2
  if grep -q "oracle=DIFF_mismatch" "$TMP/netout.txt"; then
    echo "PASS  Cross-library differential detects divergent nettle backend (DIFF_mismatch)"; pass=$((pass+1))
  else
    echo "FAIL  Cross-library differential nettle (expected DIFF_mismatch)"; fail=$((fail+1))
  fi
else
  echo "SKIP  nettle cross-library self-test (nettle-dev not installed)"
fi

# Stage 3 ecosystem: Bouncy Castle (Java) cross-language differential self-test.
# Only if a JDK is present; build_java_diff.sh compiles + emits a fault wrapper.
if command -v javac >/dev/null 2>&1 && command -v java >/dev/null 2>&1; then
  echo "[neg] building fault-injected Bouncy Castle (Java) backend..."
  bash "$ROOT/scripts/build_java_diff.sh" fault >/dev/null 2>&1
  "$ROOT/build/harness/diff_subproc" 200 12345 bouncycastle_fault="$ROOT/build/harness/compute_bouncycastle_fault" > "$TMP/bcout.txt" 2>&1 || true
  cat "$TMP/bcout.txt" >&2
  if grep -q "oracle=DIFF_mismatch" "$TMP/bcout.txt"; then
    echo "PASS  Cross-language differential detects divergent Bouncy Castle backend (DIFF_mismatch)"; pass=$((pass+1))
  else
    echo "FAIL  Cross-language differential Bouncy Castle (expected DIFF_mismatch)"; fail=$((fail+1))
  fi
  # Rebuild the clean (non-fault) wrapper so later steps don't reuse the fault one.
  bash "$ROOT/scripts/build_java_diff.sh" >/dev/null 2>&1 || true
else
  echo "SKIP  Bouncy Castle cross-language self-test (JDK not installed)"
fi

# Stage 2.5 FHE oracles self-test: OpenFHE<->SEAL BFV cross-library differential
# (O1) + SEAL CKKS approximate-arithmetic error bound (O2). Only if both FHE
# libraries are already built (OpenFHE is heavy; build_fhe_diff.sh builds it on
# demand, but here we just compile the fault harnesses against the prebuilt libs).
SEAL_A=$(ls "$ROOT/libs/SEAL/build/lib/"libseal-*.a 2>/dev/null | head -1 || true)
OFHE_A="$ROOT/libs/openfhe/build/lib/libOPENFHEpke_static.a"
if [ -n "$SEAL_A" ] && [ -f "$OFHE_A" ]; then
  echo "[neg] building fault-injected FHE oracles (OpenFHE<->SEAL BFV + SEAL CKKS)..."
  bash "$ROOT/scripts/build_fhe_diff.sh" fault >/dev/null 2>&1
  "$ROOT/build/harness/fhe_diff_fault" 20 12345 > "$TMP/fhediff.txt" 2>&1 || true
  cat "$TMP/fhediff.txt" >&2
  if grep -q "oracle=O1_fhe_bfv_interop" "$TMP/fhediff.txt"; then
    echo "PASS  FHE differential detects OpenFHE<->SEAL BFV divergence (O1_fhe_bfv_interop)"; pass=$((pass+1))
  else
    echo "FAIL  FHE differential (expected O1_fhe_bfv_interop)"; fail=$((fail+1))
  fi
  "$ROOT/build/harness/fhe_ckks_fault" 20 12345 > "$TMP/fheckks.txt" 2>&1 || true
  cat "$TMP/fheckks.txt" >&2
  if grep -q "oracle=O2_ckks_error_bound" "$TMP/fheckks.txt"; then
    echo "PASS  CKKS error-bound oracle detects out-of-bound result (O2_ckks_error_bound)"; pass=$((pass+1))
  else
    echo "FAIL  CKKS error-bound oracle (expected O2_ckks_error_bound)"; fail=$((fail+1))
  fi
  if [ -x "$ROOT/build/harness/fhe_ckks_diff_fault" ]; then
    "$ROOT/build/harness/fhe_ckks_diff_fault" 20 12345 > "$TMP/fheckksdiff.txt" 2>&1 || true
    cat "$TMP/fheckksdiff.txt" >&2
    if grep -q "oracle=O1_ckks_interop" "$TMP/fheckksdiff.txt"; then
      echo "PASS  CKKS cross-library differential detects OpenFHE<->SEAL divergence (O1_ckks_interop)"; pass=$((pass+1))
    else
      echo "FAIL  CKKS cross-library differential (expected O1_ckks_interop)"; fail=$((fail+1))
    fi
  fi
  # Rebuild clean (non-fault) FHE binaries so later steps don't reuse fault ones.
  bash "$ROOT/scripts/build_fhe_diff.sh" >/dev/null 2>&1 || true
else
  echo "SKIP  FHE oracle self-tests (OpenFHE/SEAL not built; run scripts/build_openfhe.sh + build_seal.sh)"
fi

# Stage 3 ecosystem: TFHE-rs homomorphic-integer correctness oracle self-test.
# Heavy (Rust FHE); only runs if the oracle was already built (build_tfhe.sh),
# so the base image build — which does not compile TFHE-rs — skips it.
if [ -x "$ROOT/build/harness/cmf_tfhe" ] && command -v cargo >/dev/null 2>&1; then
  echo "[neg] building fault-injected TFHE-rs oracle..."
  bash "$ROOT/scripts/build_tfhe.sh" fault >/dev/null 2>&1
  "$ROOT/build/harness/cmf_tfhe_fault" 1 12345 > "$TMP/tfhe.txt" 2>&1 || true
  cat "$TMP/tfhe.txt" >&2
  if grep -q "oracle=O_tfhe_int_correctness" "$TMP/tfhe.txt"; then
    echo "PASS  TFHE-rs oracle detects corrupted homomorphic result (O_tfhe_int_correctness)"; pass=$((pass+1))
  else
    echo "FAIL  TFHE-rs oracle (expected O_tfhe_int_correctness)"; fail=$((fail+1))
  fi
  # build_tfhe.sh already restored the clean (non-fault) binary.
else
  echo "SKIP  TFHE-rs oracle self-test (not built; run scripts/build_tfhe.sh)"
fi

# Stage 4 exploration: arkworks Groth16 zk-SNARK oracle self-test. Only runs if
# the oracle was already built (build_zk.sh); the base image does not build it.
if [ -x "$ROOT/build/harness/cmf_zk" ] && command -v cargo >/dev/null 2>&1; then
  echo "[neg] building fault-injected ZK (Groth16) oracle..."
  bash "$ROOT/scripts/build_zk.sh" fault >/dev/null 2>&1
  "$ROOT/build/harness/cmf_zk_fault" 1 12345 > "$TMP/zk.txt" 2>&1 || true
  cat "$TMP/zk.txt" >&2
  if grep -q "oracle=O_zk_groth16_verify" "$TMP/zk.txt"; then
    echo "PASS  Groth16 oracle detects broken verifier (O_zk_groth16_verify)"; pass=$((pass+1))
  else
    echo "FAIL  Groth16 oracle (expected O_zk_groth16_verify)"; fail=$((fail+1))
  fi
  # build_zk.sh already restored the clean (non-fault) binary.
else
  echo "SKIP  ZK Groth16 oracle self-test (not built; run scripts/build_zk.sh)"
fi

echo "[neg] $pass passed, $fail failed"
rm -rf "$TMP"
[ "$fail" -eq 0 ]
