#!/usr/bin/env bash
# Push project source (not built libs/artefacts) to the user's local workspace
# via the cpolar tunnel file-server REST API. Files land under <workspace>/cmfuzz/.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${CMF_TUNNEL:-http://401e9bcb.r8.cpolar.cn}"
AUTH="${CMF_TUNNEL_AUTH:-Bearer fe1c009b3eccb2862a4b98e82f22be3f}"
DEST_PREFIX="cmfuzz"

cd "$ROOT"
mapfile -t files < <(find . -type f \
  | grep -vE '^\./libs/|^\./build/|/corpus/|/crashes_|\.o$|\.a$|/__pycache__/|/crash-' )

ok=0; err=0
for f in "${files[@]}"; do
  rel="${f#./}"
  # tunnel uses Windows-style backslash paths under the workspace
  winrel="${DEST_PREFIX}\\${rel//\//\\}"
  code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "Authorization: $AUTH" -H "Content-Type: application/octet-stream" \
    --data-binary "@$f" \
    "$BASE/api/file?path=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$winrel")")
  if [ "$code" = "200" ] || [ "$code" = "201" ]; then ok=$((ok+1)); else err=$((err+1)); echo "ERR $code $rel"; fi
done
echo "[sync] uploaded=$ok failed=$err (dest: <workspace>\\$DEST_PREFIX\\)"
