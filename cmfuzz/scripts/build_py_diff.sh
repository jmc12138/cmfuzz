#!/usr/bin/env bash
# Build the stage-3 Python cross-language differential (PyCryptodome vs OpenSSL).
# PyCryptodome is an independent implementation (not an OpenSSL wrapper), so
# byte-exact agreement is a real cross-language O1 differential.
#
# No compilation is needed for the Python backend itself; this script builds the
# OpenSSL reference runner (if absent) and emits executable wrappers so the
# runner can drive `python3 compute_pycryptodome.py` as a child process.
# Passing any argument emits the fault-injected wrapper (CMF_PY_FAULT=1).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUB="$ROOT/harness/subproc"
OUT="$ROOT/build/harness"
mkdir -p "$OUT"

CC="${CC:-cc}"
[ -x "$OUT/diff_subproc" ] || $CC -g -O1 "$SUB/diff_subproc_runner.c" -I"$SUB" -lcrypto -o "$OUT/diff_subproc"

PY="${PYTHON:-python3}"
SCRIPT="$SUB/compute_pycryptodome.py"

mk_wrapper() {  # $1 = out path, $2 = extra "VAR=val" env assignments (may be empty)
  cat > "$1" <<EOF
#!/usr/bin/env bash
exec env $2 "$PY" "$SCRIPT" "\$@"
EOF
  chmod +x "$1"
}

mk_wrapper "$OUT/compute_pycryptodome" ""
echo "[build] compute_pycryptodome wrapper -> $OUT/compute_pycryptodome"
if [ -n "${1:-}" ]; then
  mk_wrapper "$OUT/compute_pycryptodome_fault" "CMF_PY_FAULT=1"
  echo "[build] compute_pycryptodome_fault wrapper -> $OUT/compute_pycryptodome_fault"
fi
