#!/usr/bin/env bash
# Phase 1 feasibility run: a live Claude Agent SDK agent whose tool calls go
# through aegis. Starts the echo upstream and a dev gateway, registers an agent
# allowlisted for "echo" only, runs the agent, then prints the audit records.
#
# Needs: the dev Postgres from the README quickstart, `npm run build` done in
# the repo root, and the Anthropic API key in the macOS Keychain under service
# "aegis-anthropic-api" (read by the agent process, never exported here).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export NODE_NO_WARNINGS=1

: "${DATABASE_URL:=postgres://aegis:dev@localhost:5432/aegis}"   # the quickstart database
: "${AUDIT_MASTER_KEY:=$(node -e "process.stdout.write(Buffer.alloc(32).toString('base64'))")}"
: "${GATEWAY_PORT:=8090}"
: "${ECHO_PORT:=7070}"
export DATABASE_URL AUDIT_MASTER_KEY

LOG_DIR="$HERE/runs"; mkdir -p "$LOG_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; rm -f "$HERE/.agent.json"; }
trap cleanup EXIT INT TERM

wait_http() { for _ in $(seq 1 30); do curl -sf -o /dev/null -m 1 "$1" && return 0; sleep 0.5; done; return 1; }

ECHO_PORT=$ECHO_PORT node "$ROOT/scripts/echo-upstream.mjs" > "$LOG_DIR/echo-$STAMP.log" 2>&1 & PIDS+=($!)
(cd "$ROOT" && PORT=$GATEWAY_PORT node dist/index.js) > "$LOG_DIR/gateway-$STAMP.log" 2>&1 & PIDS+=($!)
wait_http "http://localhost:$GATEWAY_PORT/health" || { tail -20 "$LOG_DIR/gateway-$STAMP.log"; echo "gateway not ready"; exit 1; }

START_SEQ=$(psql "$DATABASE_URL" -Atc "select coalesce(max(seq),0) from audit_records")

REG=$(cd "$ROOT" && npx tsx scripts/register.ts \
  --name "claude-live-$STAMP" --tenant claude-live \
  --tool echo \
  --cred-target mcp:echo --cred-secret "echo-backend-bearer-$STAMP" \
  --upstream-url "http://localhost:$ECHO_PORT")
umask 077
printf '%s' "$REG" | node -e '
const o=JSON.parse(require("fs").readFileSync(0,"utf8"));
process.stdout.write(JSON.stringify({agentId:o.agentId,apiKey:o.apiKey,gateway:process.argv[1]}));
' "http://localhost:$GATEWAY_PORT" > "$HERE/.agent.json"
echo "registered agent claude-live-$STAMP (allowlist: echo)"

set +e
(cd "$HERE" && npx tsx feasibility.ts) 2>&1 | tee "$LOG_DIR/agent-$STAMP.log"
RC=${PIPESTATUS[0]}
set -e

echo; echo "=== aegis audit records written by this run ==="
psql "$DATABASE_URL" -c "
  select seq, verdict, what->>'target' as target, why->>'reason' as reason,
         who#>>'{identity,agent}' as agent, ts
  from audit_records where seq > $START_SEQ order by seq;"
(cd "$ROOT" && npm run -s verify)
exit "$RC"
