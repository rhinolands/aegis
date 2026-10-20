# shellcheck shell=bash
# Shared setup for run-live.sh and demo-live.sh. Source it, do not run it.
# Starts the tool backend and a dev gateway, registers an agent allowlisted for
# read_file and http_get (each with an operator-registered destination on the
# backend), and writes the agent's gateway identity to .agent.json.

HERE="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export NODE_NO_WARNINGS=1

: "${DATABASE_URL:=postgres://aegis:dev@localhost:5432/aegis}"   # the quickstart database
: "${AUDIT_MASTER_KEY:=$(node -e "process.stdout.write(Buffer.alloc(32).toString('base64'))")}"
: "${GATEWAY_PORT:=8090}"
: "${BACKEND_PORT:=7071}"
export DATABASE_URL AUDIT_MASTER_KEY

PIDS=()
live_cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; rm -f "$HERE/.agent.json"; }
trap live_cleanup EXIT INT TERM
wait_http() { for _ in $(seq 1 30); do curl -sf -o /dev/null -m 1 "$1" && return 0; sleep 0.5; done; return 1; }

# live_policy: the product bundle plus this example's argument constraints
# (policy/constraints.rego), compiled to the example's own WASM. The gateway
# loads it through POLICY_WASM, so the product dist/policy.wasm is untouched.
live_policy() {
  mkdir -p "$HERE/dist"
  (cd "$ROOT" && opa build -t wasm -e gateway/decision --ignore '*_test.rego' \
    -o "$HERE/dist/bundle.tar.gz" policy/bundle "$HERE/policy")
  tar -xzf "$HERE/dist/bundle.tar.gz" -C "$HERE/dist" /policy.wasm 2>/dev/null
  export POLICY_WASM="$HERE/dist/policy.wasm"
}

# live_start <run-dir>: backend + gateway, logs into the run dir.
live_start() {
  local dir="$1"
  live_policy
  export BACKEND_LOG="$dir/backend.jsonl"; : > "$BACKEND_LOG"
  BACKEND_PORT=$BACKEND_PORT node "$HERE/tool-backend.mjs" > "$dir/backend.out" 2>&1 & PIDS+=($!)
  (cd "$ROOT" && PORT=$GATEWAY_PORT node dist/index.js) > "$dir/gateway.log" 2>&1 & PIDS+=($!)
  wait_http "http://localhost:$GATEWAY_PORT/health" || { tail -20 "$dir/gateway.log"; echo "gateway not ready"; return 1; }
  START_SEQ=$(psql "$DATABASE_URL" -Atc "select coalesce(max(seq),0) from audit_records")
}

# live_register <agent-name>: register + second tool credential + .agent.json.
live_register() {
  local name="$1" backend="http://localhost:$BACKEND_PORT"
  local secret   # dev placeholder; the agent never sees it
  secret="tool-backend-bearer-$(date +%s)"
  local reg
  reg=$(cd "$ROOT" && "$ROOT/node_modules/.bin/tsx" scripts/register.ts --name "$name" --tenant claude-live \
    --tool read_file,http_get \
    --cred-target mcp:read_file --cred-secret "$secret" --upstream-url "$backend/read_file")
  printf '%s' "$secret" | (cd "$ROOT" && "$ROOT/node_modules/.bin/tsx" scripts/update-agent.ts --agent-name "$name" \
    --mcp-tool http_get --mcp-upstream-base "$backend" --secret-stdin) > /dev/null
  ( umask 077
    printf '%s' "$reg" | node -e '
const o=JSON.parse(require("fs").readFileSync(0,"utf8"));
process.stdout.write(JSON.stringify({agentId:o.agentId,apiKey:o.apiKey,gateway:process.argv[1]}));
' "http://localhost:$GATEWAY_PORT" > "$HERE/.agent.json" )
}

# live_collect <run-dir>: audit rows written since live_start, plus chain verify.
live_collect() {
  local dir="$1"
  psql "$DATABASE_URL" -At -F $'\t' -c "
    select seq, verdict, what->>'target', why->>'reason', when_where->>'correlationId'
    from audit_records where seq > $START_SEQ order by seq" > "$dir/audit.tsv"
  (cd "$ROOT" && npm run -s verify) > "$dir/verify.json"
}
