#!/usr/bin/env bash
# Guided scanner run: offline checks -> preflight -> plan -> explicit confirmation -> run.
# Usage: run/run-sample.sh CONFIG.yaml [--yes-run]
# Without --yes-run no target probes are sent. Online preflight uses public-IP
# lookup services, may ping the gateway and queries the DNS canary.
set -euo pipefail
CONFIG=${1:?usage: $0 CONFIG.yaml [--yes-run|--offline-only]}
MODE=${2:-}
case "$MODE" in ""|--yes-run|--offline-only) ;; *) echo "unknown mode: $MODE" >&2; exit 2 ;; esac
cd "$(dirname "$0")/.."
PY=${SCANNER_PYTHON:-$HOME/scanner-venv/bin/python}
[ -x "$PY" ] || { echo "python venv not found at $PY (run run/setup-wsl.sh)" >&2; exit 2; }
export PYTHONDONTWRITEBYTECODE=1

echo "== 1/4 offline test suite"
"$PY" -m pytest tests/test_*.py -q -p no:cacheprovider

echo "== 2/4 preflight"
if [ "$MODE" = "--offline-only" ]; then
  "$PY" -m scanner.internet preflight --config "$CONFIG" --offline
  exit $?
fi
"$PY" -m scanner.internet preflight --config "$CONFIG"

echo "== 3/4 plan (nothing is sent)"
PLAN=$("$PY" -m scanner.internet plan --config "$CONFIG")
echo "$PLAN"
TOKEN=$(echo "$PLAN" | sed -n 's/.*"confirm_token": "\([0-9a-f]*\)".*/\1/p')
[ -n "$TOKEN" ] || { echo "no confirmation token produced" >&2; exit 2; }
SHARDS=$(echo "$PLAN" | sed -n 's/.*"shards": \([0-9]*\),*$/\1/p' | head -1)
VERB=run; [ "${SHARDS:-1}" -gt 1 ] && VERB=campaign

if [ "$MODE" != "--yes-run" ]; then
  echo
echo "Stopped before target probing. Online preflight contacted IP lookup services and the DNS canary."
echo "Review the plan above, then re-run with --yes-run only within documented approval."
  exit 0
fi

echo "== 4/4 $VERB (touch the kill-switch file named in the config to stop; run inside tmux or screen so a dropped SSH"
echo "       session cannot end it; if it stops, run this same command again: a campaign resumes at the unfinished shard)"
START=$(date +%s)
"$PY" -m scanner.internet "$VERB" --config "$CONFIG" --confirm "$TOKEN"
echo "elapsed wall-clock: $(( $(date +%s) - START )) s"
