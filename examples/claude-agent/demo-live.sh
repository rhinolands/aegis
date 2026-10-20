#!/usr/bin/env bash
# Live demo: a real Claude agent (Agent SDK) governed by aegis, end to end.
#   1. register the agent (aegis allowlist: read_file, http_get)
#   2. the agent works a task; aegis allows or denies each tool call
#   3. the audit log, joined to what actually executed
#   4. hash chain verification
# Needs the Anthropic API key in the macOS Keychain (service aegis-anthropic-api).
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/live-env.sh"

if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; R=$'\033[31m'; C=$'\033[36m'; X=$'\033[0m'; else B=; D=; G=; R=; C=; X=; fi
section() { printf '\n%s%s=== %s ===%s\n' "$B" "$C" "$1" "$X"; }

STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$HERE/runs/$STAMP-demo"; mkdir -p "$RUN_DIR"
export RUN_TAG="demo" CALLS_OUT="$RUN_DIR/calls.json"
live_start "$RUN_DIR"

section "1. Register a Claude agent with aegis"
live_register "claude-ops-$STAMP"
printf '%s    agent claude-ops-%s%s\n' "$D" "$STAMP" "$X"
printf '    tools offered to Claude:  read_file, http_get, request_credential, delete_records\n'
printf '    aegis allowlist:          %sread_file, http_get%s   (everything else: deny by default)\n' "$G" "$X"
printf '%s    the agent holds only its own aegis key. backend credentials stay in aegis.%s\n' "$D" "$X"

(cd "$HERE" && "$HERE/node_modules/.bin/tsx" demo.ts)

live_collect "$RUN_DIR"
section "3. Every call is in the aegis audit log, joined to what actually ran"
node -e '
const fs=require("fs"), dir=process.argv[1], tty=process.stdout.isTTY;
const col=(c,s)=>tty?`\x1b[${c}m${s}\x1b[0m`:s;
const ran=new Set(fs.readFileSync(dir+"/backend.jsonl","utf8").trim().split("\n").filter(Boolean).map(l=>JSON.parse(l).correlationId));
console.log(col("2","    seq  verdict  target                   reason            reached backend"));
for (const l of fs.readFileSync(dir+"/audit.tsv","utf8").trim().split("\n").filter(Boolean)) {
  const [seq,v,target,reason,cid]=l.split("\t");
  const vv=v==="allow"?col("32","allow  "):col("31","deny   ");
  console.log(`    ${seq.padEnd(4)} ${vv}  ${target.padEnd(24)} ${reason.padEnd(17)} ${ran.has(cid)?"yes":"no"}`);
}' "$RUN_DIR"

section "4. Verify the hash chain"
printf '    %s\n' "$(cat "$RUN_DIR/verify.json")"
grep -q '"ok":true' "$RUN_DIR/verify.json" && printf '    %sPASS%s: every record, allow and deny, is intact and in order\n' "$G" "$X" \
  || printf '    %sFAIL%s\n' "$R" "$X"

section "DEMO COMPLETE"
