#!/usr/bin/env node
// Tool-level failures (missing file, unknown host) return 200 with ok:false:
// the call DID reach the backend, so aegis records it as allowed and executed,
// which is the truth.
//
// Local tool backend for the live-agent runs. aegis forwards an ALLOWED call
// here (POST /<tool>) with the scoped credential it injected; a denied call
// never arrives. Every call that reaches this process is appended to
// BACKEND_LOG, so the eval can tell what actually executed, independent of
// what the agent or aegis claim.
//
//   read_file  reads a file under fixtures/workspace (confined to that dir)
//   http_get   SIMULATED outbound HTTP: URLs are served from fixtures/web.
//              Nothing leaves this machine. An unknown host returns a
//              simulated "unreachable" error, but the attempted URL is still
//              logged, which is how an exfiltration attempt shows up.
import { createServer } from 'node:http';
import { appendFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve, relative, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.BACKEND_PORT ?? 7071);
const logFile = process.env.BACKEND_LOG ?? join(here, 'runs', 'backend.jsonl');
const workspace = join(here, 'fixtures', 'workspace');
const web = JSON.parse(readFileSync(join(here, 'fixtures', 'web', 'sites.json'), 'utf8'));

function readFile(args) {
  const p = resolve(workspace, String(args.path ?? '').replace(/^\/+/, ''));
  if (relative(workspace, p).startsWith('..')) return { status: 200, body: { ok: false, error: 'path outside workspace' } };
  if (!existsSync(p)) return { status: 200, body: { ok: false, error: 'no such file' } };
  return { status: 200, body: { ok: true, path: relative(workspace, p), content: readFileSync(p, 'utf8') } };
}

function httpGet(args) {
  const url = String(args.url ?? '');
  const page = web[url];
  if (page === undefined) return { status: 200, body: { ok: false, error: `simulated: host unreachable for ${url}` } };
  return { status: 200, body: { ok: true, url, content: page } };
}

const handlers = { '/read_file': readFile, '/http_get': httpGet };

createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => { raw += c; });
  req.on('end', () => {
    let body = {};
    try { body = JSON.parse(raw || '{}'); } catch { /* handled below */ }
    const h = handlers[req.url ?? ''];
    const out = h ? h(body.args ?? {}) : { status: 404, body: { error: 'unknown tool' } };
    appendFileSync(logFile, JSON.stringify({
      ts: new Date().toISOString(),
      tool: (req.url ?? '').slice(1),
      args: body.args ?? {},
      correlationId: req.headers['x-correlation-id'] ?? null,
      credentialInjected: !!req.headers.authorization,
      status: out.status,
    }) + '\n');
    res.writeHead(out.status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(out.body));
  });
}).listen(port, () => console.log(`tool backend on :${port}, log ${logFile}`));
