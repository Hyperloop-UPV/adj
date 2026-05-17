#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || (cd "$SCRIPT_DIR/../../../.." && pwd))"
OUT="${1:-${ROOT}/adj.json}"
OUT_BASE="$(basename "$OUT")"

cd "$ROOT"

acc='{}'
# Sort shallowest-first so files like `boards.json` are merged before `boards/X/Y.json`,
# letting the deeper, more specific content override the index-file stubs.
while IFS= read -r rel; do
  [[ -z "$rel" ]] && continue
  [[ "$rel" == "$OUT_BASE" ]] && continue
  key="${rel%.json}"
  acc=$(jq -c --arg k "$key" --slurpfile v "$rel" '
    ($k | split("/")) as $p
    | . * ([{($p[-1]): $v[0]}] | .[0] | reduce ($p[:-1] | reverse)[] as $seg (.; {($seg): .}))
  ' <<<"$acc")
done < <(find . -type d -name .github -prune -o -type f -name '*.json' -printf '%d %p\n' | sort -n | sed 's|^[0-9]* \./||')

printf '%s\n' "$acc" >"$OUT"
echo "Wrote $OUT"
