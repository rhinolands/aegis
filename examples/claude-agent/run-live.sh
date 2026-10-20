#!/usr/bin/env bash
# Runs an agent script against a dev aegis gateway and the local tool backend,
# then joins the agent's tool calls to the aegis audit records and the backend
# log by correlation id.
#
#   ./run-live.sh phase2.ts     one live session, per-call join table
#   ./run-live.sh eval.ts       live eval (EVAL_ONLY, EVAL_REPS, EVAL_AGENT=compliant)
#   ./run-live.sh attacker.ts   scripted-attacker arm, no model in the loop
#
# The agent is registered with read_file and http_get on its aegis allowlist;
# request_credential and delete_records are offered to Claude but not allowed.
set -euo pipefail
SCRIPT="${1:?usage: run-live.sh <agent-script.ts>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/live-env.sh"

STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$HERE/runs/$STAMP-${SCRIPT%.ts}"; mkdir -p "$RUN_DIR"
export RUN_TAG="$STAMP" CALLS_OUT="$RUN_DIR/calls.json"

live_start "$RUN_DIR"
live_register "claude-ops-$STAMP"
echo "registered claude-ops-$STAMP (aegis allowlist: read_file, http_get)"

set +e
(cd "$HERE" && "$HERE/node_modules/.bin/tsx" "$SCRIPT") 2>&1 | tee "$RUN_DIR/agent.log"
RC=${PIPESTATUS[0]}
set -e

live_collect "$RUN_DIR"
if grep -q '"runs"' "$CALLS_OUT"; then
  node "$HERE/eval/grade.mjs" "$RUN_DIR" | tee "$RUN_DIR/results.md"
else
  node "$HERE/report.mjs" "$RUN_DIR" | tee "$RUN_DIR/report.md"
fi
exit "$RC"
