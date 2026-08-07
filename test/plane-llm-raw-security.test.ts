/**
 * Security proofs for the G1 raw route (POST /v1/messages).
 *
 * Two of these are ports of proofs that already exist for the envelope route
 * (test/plane-llm.test.ts:168-207 and :262-312). They are ported rather than
 * shared because G1 is a NEW route that re-opens both surfaces: it accepts a
 * caller-controlled passthrough body and it makes its own outbound fetch.
 *
 * DELIBERATELY NOT CARRIED from the analog suite, so nobody "restores" them:
 *   - the `openai` upstream-style test — G1 is anthropic-compat only and has
 *     no style switch to get wrong;
 *   - the `payload.model` override test — G1 has no envelope merge, so there
 *     is no `{...payload, model}` spread order and therefore no bypass to
 *     guard. The equivalent property here is that the model OPA gated is the
 *     model that reaches the upstream, which the fidelity suite asserts.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createServer, type Server, type IncomingMessage } from 'node:http';
import { randomUUID } from 'node:crypto';
import { sql as dsql } from 'drizzle-orm';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { loadPolicy, type PolicyEngine } from '../src/policy/opa.js';
import { registerAgent } from '../src/identity/registry.js';
import { putCredential } from '../src/credentials/store.js';
import { seedBudget } from '../src/guard/budget.js';
import { buildServer } from '../src/server.js';
import { auditRecords } from '../src/db/schema.js';

const cfg = loadConfig(process.env);
let engine: PolicyEngine;
beforeAll(async () => { engine = await loadPolicy('dist/policy.wasm'); });

// Priced in MODEL_PRICES, so metering runs rather than falling through the
// unpriced path.
const MODEL = 'claude-sonnet-4-6';

interface RecordedRequest {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingMessage['headers'];
  raw: string;
  body: unknown;
}

/** Ephemeral upstream that records every request it receives. */
function startUpstream(usage?: Record<string, unknown>): Promise<{ server: Server; port: number; requests: RecordedRequest[] }> {
  const requests: RecordedRequest[] = [];
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let body: unknown = {};
        try { body = raw ? JSON.parse(raw) : {}; } catch { body = raw; }
        requests.push({ method: req.method, url: req.url, headers: req.headers, raw, body });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, ...(usage ? { usage } : {}) }));
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, port: typeof addr === 'object' && addr ? addr.port : 0, requests });
    });
  });
}

describe('POST /v1/messages — security', () => {
  it('SECURITY: ignores a caller-supplied upstream URL in the body and never contacts the attacker-controlled server', async () => {
    const { db, sql } = getDb(cfg);
    const legit = await startUpstream({ input_tokens: 10, output_tokens: 5 });
    const attacker = await startUpstream({ input_tokens: 1, output_tokens: 1 });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawsec-exfil-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // The credential is registered against the LEGITIMATE upstream only.
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${legit.port}`);
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: {
          model: MODEL,
          max_tokens: 16,
          messages: [{ role: 'user', content: 'hi' }],
          // There is no `payload` envelope on this route, so the attacker
          // plants the destination as a stray top-level field. The property
          // being proven is identical to the analog's: the body can never
          // become a destination.
          upstreamUrl: `http://127.0.0.1:${attacker.port}`,
          base_url: `http://127.0.0.1:${attacker.port}`,
        },
      });

      expect(res.statusCode).toBe(200);
      // The attacker server must receive ZERO requests.
      expect(attacker.requests.length).toBe(0);
      // The legitimate, operator-registered upstream received exactly one.
      expect(legit.requests.length).toBe(1);
      expect(legit.requests[0].headers['x-api-key']).toBe('anthropic-key-xyz');

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => legit.server.close(r));
      await new Promise((r) => attacker.server.close(r));
    }
  });

  it('SECURITY: does not follow a redirect from the registered upstream and makes zero requests to the redirect target', async () => {
    const { db, sql } = getDb(cfg);
    const attacker = await startUpstream();
    let redirector: Server | undefined;
    try {
      // A "registered" upstream that always answers 302 pointing at the
      // attacker — a compromised registered destination trying to hop the
      // mediated call, and its injected credential, somewhere unauthorized.
      const redirectorPort: number = await new Promise((resolve) => {
        const server = createServer((_req, res) => {
          res.writeHead(302, { location: `http://127.0.0.1:${attacker.port}/v1/messages` });
          res.end();
        });
        redirector = server;
        server.listen(0, '127.0.0.1', () => {
          const addr = server.address();
          resolve(typeof addr === 'object' && addr ? addr.port : 0);
        });
      });

      const { agent, apiKey } = await registerAgent(db, { name: `rawsec-redir-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${redirectorPort}`);
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/messages',
        headers: { 'x-api-key': apiKey },
        payload: { model: MODEL, max_tokens: 16, messages: [] },
      });

      // NOTE FOR A FUTURE READER: the analog at test/plane-llm.test.ts:300
      // expects 403 here, because the envelope route collapses every upstream
      // failure into a governance deny. G1 relays instead, so a refused
      // redirect is a gateway-side upstream failure: 502. Do not "fix" this
      // back to 403 — that would be the collapse this route exists to remove.
      expect(res.statusCode).toBe(502);
      const body = JSON.parse(res.body) as { error?: { type?: string } };
      expect(body.error?.type).toBe('api_error');
      // The attacker server must receive ZERO requests. This locks the
      // behaviour in our own code (manual redirect handling + explicit
      // rejection) rather than relying on undici incidentally stripping
      // credentials on a cross-origin hop.
      expect(attacker.requests.length).toBe(0);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => attacker.server.close(r));
      if (redirector) await new Promise((r) => redirector!.close(r));
    }
  });

  it('SECURITY: forwards headers by allowlist — a caller Authorization header never reaches the upstream, and x-api-key is the REGISTERED secret', async () => {
    const { db, sql } = getDb(cfg);
    const legit = await startUpstream({ input_tokens: 10, output_tokens: 5 });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `rawsec-hdr-${Date.now()}`, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${legit.port}`);
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/messages?beta=true',
        headers: {
          'x-api-key': apiKey,
          // src/auth/authenticate.ts also accepts a Bearer JWT, which is why
          // the forwarding rule has to be an allowlist: a blocklist that only
          // stripped x-api-key would hand this token to Anthropic.
          authorization: 'Bearer caller-supplied-jwt-should-never-leave-the-gateway',
          'anthropic-version': '2023-06-01',
          'anthropic-beta': 'structured-outputs-2025-12-15',
          'x-stainless-lang': 'js',
        },
        payload: { model: MODEL, max_tokens: 16, messages: [] },
      });

      expect(res.statusCode).toBe(200);
      expect(legit.requests.length).toBe(1);
      const received = legit.requests[0];
      // No Authorization header may appear on the upstream request at all.
      expect(received.headers['authorization']).toBeUndefined();
      expect(Object.keys(received.headers).map((k) => k.toLowerCase())).not.toContain('authorization');
      // The beta signal is the ONLY carrier of structured-output behaviour
      // (kill-finding K2) — it must arrive verbatim.
      expect(received.headers['anthropic-beta']).toBe('structured-outputs-2025-12-15');
      expect(received.headers['anthropic-version']).toBe('2023-06-01');
      expect(received.headers['x-stainless-lang']).toBe('js');
      // The upstream sees the registered secret, never the caller's gateway key.
      expect(received.headers['x-api-key']).toBe('anthropic-key-xyz');
      expect(received.headers['x-api-key']).not.toBe(apiKey);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => legit.server.close(r));
    }
  });

  it('SECURITY: identity is derived from the presented credential — a body claiming another agent or tenant does not change the audit record', async () => {
    const { db, sql } = getDb(cfg);
    const legit = await startUpstream({ input_tokens: 10, output_tokens: 5 });
    try {
      const name = `rawsec-ident-${Date.now()}`;
      const { agent, apiKey } = await registerAgent(db, { name, tenant: 'test', allowedModels: [MODEL] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${legit.port}`);
      const app = buildServer({ cfg, db, engine });

      const correlationId = randomUUID();
      const res = await app.inject({
        method: 'POST',
        url: '/v1/messages',
        headers: { 'x-api-key': apiKey, 'x-correlation-id': correlationId },
        payload: {
          model: MODEL,
          max_tokens: 16,
          messages: [],
          // Caller-supplied identity claims, which the gateway must ignore.
          agent: 'some-other-agent',
          tenant: 'some-other-tenant',
        },
      });

      expect(res.statusCode).toBe(200);

      const [record] = await db
        .select()
        .from(auditRecords)
        .where(dsql`${auditRecords.whenWhere}->>'correlationId' = ${correlationId}`)
        .limit(1);
      expect(record).toBeDefined();
      expect(record.verdict).toBe('allow');
      expect((record.who as { identity?: { agent?: unknown } }).identity?.agent).toBe(name);
      expect((record.who as { identity?: { agent?: unknown } }).identity?.agent).not.toBe('some-other-agent');
      expect(record.tenant).toBe('test');
      expect(record.tenant).not.toBe('some-other-tenant');

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => legit.server.close(r));
    }
  });
});
