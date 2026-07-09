#!/usr/bin/env bash
# Run functional fuzzing campaigns for every built harness for a fixed budget,
# capturing runs/coverage/crashes into results/campaign/.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/build/harness"
RES="$ROOT/results/campaign"; mkdir -p "$RES"
SECS="${CMF_SECS:-30}"        # per-target wall-clock budget
SUMMARY="$RES/summary.tsv"
echo -e "target\truns\tcov\tfeatures\tcrashes\tstatus" > "$SUMMARY"

for bin in "$BIN"/*; do
  [ -x "$bin" ] || continue
  name="$(basename "$bin")"
  cdir="$ROOT/results/corpus/$name"; mkdir -p "$cdir"
  crashdir="$RES/crashes_$name"; mkdir -p "$crashdir"
  log="$RES/log_$name.txt"
  echo "[campaign] $name for ${SECS}s"
  # FHE (SEAL) target isn't coverage-instrumented: run as property tester w/ seeds
  extra=""; case "$name" in fhe_*) extra="-max_len=64"; head -c 48 /dev/urandom > "$cdir/seed";; esac
  timeout "$SECS" "$bin" -artifact_prefix="$crashdir/" $extra "$cdir" > "$log" 2>&1
  rc=$?
  runs=$(grep -oE "#[0-9]+" "$log" | tail -1 | tr -d '#'); runs=${runs:-0}
  cov=$(grep -oE "cov: [0-9]+" "$log" | tail -1 | awk '{print $2}'); cov=${cov:-0}
  ft=$(grep -oE "ft: [0-9]+" "$log" | tail -1 | awk '{print $2}'); ft=${ft:-0}
  crashes=$(ls "$crashdir" 2>/dev/null | wc -l | tr -d ' ')
  viol=$(grep -c CMF_VIOLATION "$log" 2>/dev/null); viol=${viol:-0}
  status="ok"; [ "$crashes" -gt 0 ] && status="CRASH"; [ "$viol" -gt 0 ] && status="VIOLATION"
  echo -e "$name\t$runs\t$cov\t$ft\t$crashes\t$status" >> "$SUMMARY"
done
echo "[campaign] summary:"; (column -t "$SUMMARY" 2>/dev/null || cat "$SUMMARY")
