#!/usr/bin/env bash
# scripts/demo.sh — the five-minute end-to-end demo for aegis (spec §5.10).
#
# Narrative, in order:
#   1. Register an agent with exactly one allowlisted tool ("echo").
#   2. ALLOWED tool call  -> 200, audit record shows who / what / why, and the
#      upstream proves the gateway injected a credential the caller never held.
#   3. UNAUTHORIZED tool call (a tool NOT on the allowlist) -> 403, deny record.
#   4. verifyChain() -> PASSES against the chain built by steps 2-3.
#   5. Tamper with the latest record as an attacker with owner DB credentials
#      would (disable the append-only trigger, edit, re-enable it), then
#      verifyChain() -> FAILS, proving the edit is caught.
#
# Self-contained: starts the echo upstream and the gateway itself if they are
# not already running, waits for readiness (no blind sleeps), and stops only
# what it started on exit. Fails loudly (non-zero exit, clear message) the
# instant any step doesn't produce the expected outcome — a demo that prints
# success regardless of what happened is worthless.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
  YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
  BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; CYAN=''; RESET=''
fi

section() { printf '\n%s%s=== %s ===%s\n' "$BOLD" "$CYAN" "$1" "$RESET"; }
info()    { printf '%s    %s%s\n' "$DIM" "$1" "$RESET"; }
pass()    { printf '%s    OK: %s%s\n' "$GREEN" "$1" "$RESET"; }

fail() {
  printf '\n%s%sFAIL: %s%s\n' "$BOLD" "$RED" "$1" "$RESET" >&2
  exit 1
}

# Presenter mode: pause between beats for a narrated or recorded walkthrough.
#   PAUSE=1  wait for Enter, showing a dim "[ Enter ]" hint (good for practice)
#   PAUSE=2  wait for Enter SILENTLY (clean frozen frame for on-screen captions)
# CI-safe: with no attached terminal (pipe/CI) it never blocks.
pause() {
  case "${PAUSE:-0}" in 1|2) ;; *) return 0 ;; esac
  [ -t 0 ] || return 0
  [ "${PAUSE}" = "1" ] && printf '\n%s    [ Enter for the next step ]%s ' "$DIM" "$RESET"
  read -r _ || true
}

# ---------------------------------------------------------------------------
# Config (all overridable; sane dev defaults so the script needs no args)
# ---------------------------------------------------------------------------
: "${DATABASE_URL:=postgres://aegis:dev@localhost:5432/aegis}"
: "${AUDIT_MASTER_KEY:=$(node -e "process.stdout.write(Buffer.alloc(32).toString('base64'))")}"
: "${PORT:=8080}"
: "${BASE:=http://localhost:${PORT}}"
: "${ECHO_PORT:=7070}"
export DATABASE_URL AUDIT_MASTER_KEY PORT

RUN_ID="$(date +%s)-$$"
AGENT_NAME="demo-agent-${RUN_ID}"
TENANT="acme-demo"
TOOL="echo"
DENIED_TOOL="danger"
CRED_TARGET="mcp:${TOOL}"
CRED_SECRET="demo-backend-bearer-not-a-real-secret-${RUN_ID}"
UPSTREAM_URL="http://localhost:${ECHO_PORT}"

MASKED_DB_URL="$(printf '%s' "$DATABASE_URL" | sed -E 's#//[^:]+:[^@]+@#//***:***@#')"

TMP_DIR="$(mktemp -d)"
GATEWAY_LOG="$TMP_DIR/gateway.log"
ECHO_LOG="$TMP_DIR/echo.log"

# ---------------------------------------------------------------------------
# Process lifecycle: only kill what we started; always clean the temp dir.
# ---------------------------------------------------------------------------
SERVER_PID=""
ECHO_PID=""
STARTED_SERVER=0
STARTED_ECHO=0

cleanup() {
  local ec=$?
  section "Cleanup"
  if [ "$STARTED_SERVER" = "1" ] && [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    info "stopped gateway we started (pid $SERVER_PID)"
  else
    info "gateway was already running externally; left it running"
  fi
  if [ "$STARTED_ECHO" = "1" ] && [ -n "$ECHO_PID" ]; then
    kill "$ECHO_PID" 2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
    info "stopped echo upstream we started (pid $ECHO_PID)"
  else
    info "echo upstream was already running externally; left it running"
  fi
  rm -rf "$TMP_DIR"
  exit "$ec"
}
trap cleanup EXIT INT TERM

wait_for_http() {
  local url="$1" desc="$2" timeout="${3:-15}" waited=0
  until curl --fail -s -o /dev/null -m 1 "$url" 2>/dev/null; do
    waited=$((waited + 1))
    if [ "$waited" -ge "$timeout" ]; then
      return 1
    fi
    sleep 0.5
  done
  return 0
}

print_record() {
  local label="$1"
  printf '%s    %s%s\n' "$DIM" "$label" "$RESET"
  psql "$DATABASE_URL" -x -q -c "
    SELECT seq,
           verdict,
           policy_version,
           who->>'agentId'                AS who_agent_id,
           who#>>'{identity,agent}'        AS who_agent_name,
           what->>'target'                 AS what_target,
           what->>'operation'              AS what_operation,
           what->>'argsDigest'             AS what_args_digest,
           why->>'reason'                  AS why_reason
    FROM audit_records
    WHERE seq = (SELECT max(seq) FROM audit_records);
  "
}

pretty_json_file() {
  node -e 'const fs=require("fs");console.log(JSON.stringify(JSON.parse(fs.readFileSync(process.argv[1],"utf8")),null,2))' "$1" \
    2>/dev/null || cat "$1"
}

SECONDS=0

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
section "Preflight"
for bin in node npx curl psql; do
  command -v "$bin" >/dev/null 2>&1 || fail "required tool not found on PATH: $bin"
done
info "database: $MASKED_DB_URL"
info "gateway:  $BASE"
info "echo upstream: $UPSTREAM_URL"

psql "$DATABASE_URL" -q -c 'SELECT 1;' >/dev/null 2>&1 \
  || fail "cannot reach Postgres at $MASKED_DB_URL (is aegis-pg running and migrated?)"
pass "Postgres reachable"

command -v opa >/dev/null 2>&1 || fail "the 'opa' binary is required to build the policy bundle (npm run build)"

# ---------------------------------------------------------------------------
# Build (compiles the Rego policy to WASM + TypeScript; ~3s when clean)
# ---------------------------------------------------------------------------
section "Build"
if npm run build > "$TMP_DIR/build.log" 2>&1; then
  pass "npm run build (dist/policy.wasm + dist/*.js)"
else
  tail -n 40 "$TMP_DIR/build.log" >&2
  fail "npm run build failed (see log above)"
fi

# ---------------------------------------------------------------------------
# Start echo upstream (skip if something is already listening there)
# ---------------------------------------------------------------------------
section "Starting services"
if wait_for_http "$UPSTREAM_URL" "echo upstream" 1; then
  info "echo upstream already running at $UPSTREAM_URL — reusing it"
else
  ECHO_PORT="$ECHO_PORT" node scripts/echo-upstream.mjs > "$ECHO_LOG" 2>&1 &
  ECHO_PID=$!
  STARTED_ECHO=1
  if ! wait_for_http "$UPSTREAM_URL" "echo upstream" 15; then
    cat "$ECHO_LOG" >&2 || true
    fail "echo upstream did not become ready on $UPSTREAM_URL within 15s"
  fi
  pass "echo upstream up (pid $ECHO_PID, :$ECHO_PORT)"
fi

# ---------------------------------------------------------------------------
# Start the gateway itself (skip if something already answers /health)
# ---------------------------------------------------------------------------
if wait_for_http "$BASE/health" "gateway" 1; then
  info "gateway already running at $BASE — reusing it"
else
  node dist/index.js > "$GATEWAY_LOG" 2>&1 &
  SERVER_PID=$!
  STARTED_SERVER=1
  if ! wait_for_http "$BASE/health" "gateway" 15; then
    tail -n 40 "$GATEWAY_LOG" >&2 || true
    fail "gateway did not become ready on $BASE/health within 15s"
  fi
  pass "gateway up (pid $SERVER_PID, $BASE)"
fi

# ---------------------------------------------------------------------------
# Clean slate: start from an unambiguous, empty hash chain.
# ---------------------------------------------------------------------------
section "Resetting to a clean chain"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -c 'TRUNCATE audit_records, chain_head;'
info "audit_records + chain_head truncated — every record below is new"
pass "clean chain"
pause  # presenter: start recording here, then Enter to begin beat 1

# ---------------------------------------------------------------------------
# Step 1: register an agent with exactly one allowlisted tool
# ---------------------------------------------------------------------------
section "1. Register agent '${AGENT_NAME}' — allowlisted tool: '${TOOL}' only"
REGISTER_OUT=$(npx tsx scripts/register.ts \
  --name "$AGENT_NAME" --tenant "$TENANT" \
  --tool "$TOOL" \
  --cred-target "$CRED_TARGET" --cred-secret "$CRED_SECRET" --upstream-url "$UPSTREAM_URL") \
  || fail "agent registration failed"

API_KEY=$(printf '%s' "$REGISTER_OUT" | node -e 'const fs=require("fs");process.stdout.write(JSON.parse(fs.readFileSync(0,"utf8")).apiKey)')
[ -n "$API_KEY" ] || fail "register.ts did not return an apiKey"

printf '%s' "$REGISTER_OUT" | node -e '
const fs=require("fs");
const o=JSON.parse(fs.readFileSync(0,"utf8"));
console.log(JSON.stringify({
  agentId: o.agentId, name: o.name, tenant: o.tenant,
  allowedTools: o.allowedTools, credentialTarget: o.credential.target,
  upstreamUrl: o.credential.upstreamUrl,
}, null, 2));
'
info "api key issued: ${API_KEY:0:14}... (never logged in full; register.ts prints it exactly once)"
pass "agent registered — it can call '${TOOL}' and nothing else"
pause

# ---------------------------------------------------------------------------
# Step 2: ALLOWED tool call
# ---------------------------------------------------------------------------
section "2. ALLOWED tool call -> mcp/${TOOL}"
ALLOW_CODE=$(curl -s -o "$TMP_DIR/allowed.json" -w '%{http_code}' \
  -X POST "$BASE/mcp/${TOOL}" \
  -H "x-api-key: $API_KEY" -H 'content-type: application/json' \
  -d '{"operation":"call","args":{"msg":"hello from the aegis demo"}}')

echo "    HTTP $ALLOW_CODE"
pretty_json_file "$TMP_DIR/allowed.json" | sed 's/^/    /'

[ "$ALLOW_CODE" = "200" ] || fail "expected 200 for the allowed tool call, got $ALLOW_CODE"
grep -q '"authSeen":true' "$TMP_DIR/allowed.json" \
  || fail "upstream did not see an Authorization header — credential injection did not happen"
pass "200 — the upstream saw authSeen:true: the gateway injected the scoped backend credential; the caller only ever held its own x-api-key"

print_record "audit record for this call (who / what / why / verdict):"
pass "allow logged"
pause

# ---------------------------------------------------------------------------
# Step 3: UNAUTHORIZED tool call (tool not on the allowlist)
# ---------------------------------------------------------------------------
section "3. UNAUTHORIZED tool call -> mcp/${DENIED_TOOL} (not allowlisted)"
DENY_CODE=$(curl -s -o "$TMP_DIR/denied.json" -w '%{http_code}' \
  -X POST "$BASE/mcp/${DENIED_TOOL}" \
  -H "x-api-key: $API_KEY" -H 'content-type: application/json' \
  -d '{"operation":"call","args":{}}')

echo "    HTTP $DENY_CODE"
pretty_json_file "$TMP_DIR/denied.json" | sed 's/^/    /'

[ "$DENY_CODE" = "403" ] || fail "expected 403 for the unauthorized tool call, got $DENY_CODE — this is the whole product; a non-403 here is a governance failure, not a demo quirk"
pass "403 — denied fail-closed by policy (tool not in the agent's allowlist)"

print_record "DENY record for this call — the deny log IS the product (who / what / why / verdict):"
pass "deny logged"
pause

# ---------------------------------------------------------------------------
# Step 4: chain verification — must PASS
# ---------------------------------------------------------------------------
section "4. Chain verification (expect PASS)"
VERIFY_1=$(node --input-type=module -e '
import { loadConfig } from "./dist/config.js";
import { getDb } from "./dist/db/client.js";
import { verifyChain } from "./dist/audit/verify.js";
const cfg = loadConfig(process.env);
const { db, sql } = getDb(cfg);
const r = await verifyChain(db);
console.log(JSON.stringify(r));
await sql.end();
')
echo "    $VERIFY_1"
printf '%s' "$VERIFY_1" | grep -q '"ok":true' \
  || fail "expected verifyChain to PASS on an untampered chain, got: $VERIFY_1"
pass "chain verified — 2 records (1 allow, 1 deny), hashes match"
pause  # dramatic beat: pressing Enter reveals the tamper attack

# ---------------------------------------------------------------------------
# Step 5: tamper as an attacker with owner DB credentials would, then re-verify
# ---------------------------------------------------------------------------
section "5. Tamper with a record (owner-DB-credentials attack), then re-verify (expect FAIL)"
BEFORE=$(psql "$DATABASE_URL" -t -A -c "SELECT seq || '|' || verdict FROM audit_records WHERE seq = (SELECT max(seq) FROM audit_records);")
info "target record before tamper: seq|verdict = $BEFORE"

# Show the attack on screen: the exact SQL an attacker with owner DB
# credentials runs. Seeing the crime is the whole point of this beat.
TAMPER_SQL="ALTER TABLE audit_records DISABLE TRIGGER trg_audit_no_mutate;
UPDATE audit_records
   SET verdict = CASE WHEN verdict = 'allow' THEN 'deny' ELSE 'allow' END
 WHERE seq = (SELECT max(seq) FROM audit_records);
ALTER TABLE audit_records ENABLE TRIGGER trg_audit_no_mutate;"
printf '%s    the attacker holds owner DB credentials and runs this straight against Postgres:%s\n' "$DIM" "$RESET"
printf '%s' "$YELLOW"; printf '%s\n' "$TAMPER_SQL" | sed 's/^/    /'; printf '%s' "$RESET"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -c "$TAMPER_SQL"
AFTER=$(psql "$DATABASE_URL" -t -A -c "SELECT seq || '|' || verdict FROM audit_records WHERE seq = (SELECT max(seq) FROM audit_records);")
info "target record after tamper:  seq|verdict = $AFTER (trigger disabled, edited, re-enabled)"

VERIFY_2=$(node --input-type=module -e '
import { loadConfig } from "./dist/config.js";
import { getDb } from "./dist/db/client.js";
import { verifyChain } from "./dist/audit/verify.js";
const cfg = loadConfig(process.env);
const { db, sql } = getDb(cfg);
const r = await verifyChain(db);
console.log(JSON.stringify(r));
await sql.end();
')
echo "    $VERIFY_2"
printf '%s' "$VERIFY_2" | grep -q '"ok":false' \
  && printf '%s' "$VERIFY_2" | grep -q 'hash mismatch' \
  || fail "expected verifyChain to FAIL with a hash mismatch after tampering, got: $VERIFY_2 — this means a tampered record would go UNDETECTED"
pass "chain verification correctly FAILED — the tampered record was caught"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
section "DEMO COMPLETE"
echo "    allow logged, deny logged, chain verified, tamper detected."
echo "    elapsed: ${SECONDS}s"
