#!/usr/bin/env bash
# Build the stage-3 Bouncy Castle cross-language differential (Java vs OpenSSL).
# Bouncy Castle is a pure-Java implementation (not an OpenSSL wrapper), so
# byte-exact agreement is a real cross-language O1 differential — Java is a fifth
# independent lineage after OpenSSL/Go/Rust/Python.
#
# Requires a JDK (javac/java). The BC provider jar is fetched on demand (pinned)
# and gitignored, like liboqs/SEAL/OpenFHE. Builds the OpenSSL reference runner
# (if absent), compiles CmfCompute.java, and emits executable wrappers so the
# runner can drive `java ... CmfCompute` as a child process. Passing any argument
# also emits the fault-injected wrapper (CMF_JAVA_FAULT=1).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUB="$ROOT/harness/subproc"
BC="$ROOT/harness/bcbridge"
OUT="$ROOT/build/harness"
JAR="$ROOT/libs/bouncycastle/bcprov.jar"
CLASSES="$OUT/bcclasses"
mkdir -p "$OUT" "$CLASSES" "$(dirname "$JAR")"

BC_REF="${BC_VERSION:-1.78.1}"
BC_SHA256="add5915e6acfc6ab5836e1fd8a5e21c6488536a8c1f21f386eeb3bf280b702d7"
if [ ! -f "$JAR" ]; then
  curl -fsSL -o "$JAR" \
    "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/${BC_REF}/bcprov-jdk18on-${BC_REF}.jar"
fi
echo "$BC_SHA256  $JAR" | sha256sum -c - >/dev/null

CC="${CC:-cc}"
[ -x "$OUT/diff_subproc" ] || $CC -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$OUT/diff_subproc"

javac -cp "$JAR" -d "$CLASSES" "$BC/CmfCompute.java"

mk_wrapper() {  # $1 = out path, $2 = extra "VAR=val" env assignments
  cat > "$1" <<EOF
#!/usr/bin/env bash
exec env $2 java -cp "$JAR:$CLASSES" CmfCompute "\$@"
EOF
  chmod +x "$1"
}

mk_wrapper "$OUT/compute_bouncycastle" ""
echo "[build] compute_bouncycastle wrapper -> $OUT/compute_bouncycastle"
if [ -n "${1:-}" ]; then
  mk_wrapper "$OUT/compute_bouncycastle_fault" "CMF_JAVA_FAULT=1"
  echo "[build] compute_bouncycastle_fault wrapper -> $OUT/compute_bouncycastle_fault"
fi
