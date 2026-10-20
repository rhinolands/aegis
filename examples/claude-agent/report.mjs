#!/usr/bin/env node
// Joins one run's three views of each tool call by correlation id:
//   what Claude asked for (calls.json), what aegis decided (audit.tsv), and
//   what actually executed at the backend (backend.jsonl).
// A call is consistent when an allow reached the backend exactly once and a
// deny never did.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.argv[2];
const { calls } = JSON.parse(readFileSync(join(dir, 'calls.json'), 'utf8'));
const audit = new Map(
  readFileSync(join(dir, 'audit.tsv'), 'utf8').trim().split('\n').filter(Boolean).map((l) => {
    const [seq, verdict, target, reason, cid] = l.split('\t');
    return [cid, { seq, verdict, target, reason }];
  }),
);
const backend = readFileSync(join(dir, 'backend.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
const verify = readFileSync(join(dir, 'verify.json'), 'utf8').trim();

const short = (o) => { const s = JSON.stringify(o); return s.length > 60 ? `${s.slice(0, 57)}...` : s; };
const rows = calls.map((c) => {
  const a = audit.get(c.correlationId);
  const executed = backend.filter((b) => b.correlationId === c.correlationId);
  const consistent = a && ((a.verdict === 'allow' && executed.length === 1) || (a.verdict === 'deny' && executed.length === 0));
  return `| ${c.correlationId} | ${c.tool} | \`${short(c.args)}\` | ${a ? `${a.verdict} (seq ${a.seq})` : 'NO AUDIT RECORD'} | ${a?.reason ?? ''} | ${executed.length ? `yes${executed[0].credentialInjected ? ', credential injected' : ''}` : 'no'} | ${consistent ? 'yes' : 'NO'} |`;
});

console.log(`| correlation id | tool | args | aegis verdict | reason | reached backend | consistent |`);
console.log(`|---|---|---|---|---|---|---|`);
console.log(rows.join('\n'));
console.log(`\nAudit records for calls: ${calls.filter((c) => audit.has(c.correlationId)).length}/${calls.length}. Chain verification: ${verify}`);
