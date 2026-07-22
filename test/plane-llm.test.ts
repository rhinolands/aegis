import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server, type IncomingMessage } from 'node:http';
import { randomUUID } from 'node:crypto';
import { eq, sql as dsql } from 'drizzle-orm';
import { getDb } from '../src/db/client.js';
import { loadConfig } from '../src/config.js';
import { loadPolicy, type PolicyEngine } from '../src/policy/opa.js';
import { registerAgent } from '../src/identity/registry.js';
import { putCredential } from '../src/credentials/store.js';
import { seedBudget } from '../src/guard/budget.js';
import { buildServer } from '../src/server.js';
import { budgets, auditRecords } from '../src/db/schema.js';

const cfg = loadConfig(process.env);
let engine: PolicyEngine;
beforeAll(async () => { engine = await loadPolicy('dist/policy.wasm'); });

// Ephemeral upstream: records every request it receives (headers + body) and
// responds 200 JSON with a usage block, mirroring an Anthropic/OpenAI-style
// completion response. This is the real assertion surface for the
// credential-injection, metering, and deny-short-circuit properties.
interface RecordedRequest { headers: IncomingMessage['headers']; body: unknown }

function startUpstream(usage?: Record<string, number>): Promise<{ server: Server; port: number; requests: RecordedRequest[] }> {
  const requests: RecordedRequest[] = [];
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let body: unknown = {};
        try { body = raw ? JSON.parse(raw) : {}; } catch { body = raw; }
        requests.push({ headers: req.headers, body });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, ...(usage ? { usage } : {}) }));
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({ server, port, requests });
    });
  });
}

describe('POST /llm/:model', () => {
  let upstream: Awaited<ReturnType<typeof startUpstream>>;

  beforeAll(async () => { upstream = await startUpstream({ input_tokens: 40, output_tokens: 60 }); });
  afterAll(async () => { await new Promise((r) => upstream.server.close(r)); });

  it('allows an allowlisted model, calls the operator-registered upstream with the correctly-formatted auth header, and meters tokens', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llm-${Date.now()}`, tenant: 'test', allowedModels: ['claude-sonnet-5'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // Operator registers the destination alongside the credential — never
      // supplied by the caller in the request body.
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}/v1/messages`);
      const app = buildServer({ cfg, db, engine });

      const before = upstream.requests.length;
      const [budgetBefore] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);

      const res = await app.inject({
        method: 'POST',
        url: '/llm/claude-sonnet-5',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'complete', payload: { messages: [] }, upstreamStyle: 'anthropic' },
      });

      expect(res.statusCode).toBe(200);
      expect(upstream.requests.length).toBe(before + 1);
      const received = upstream.requests[upstream.requests.length - 1];
      expect(received.headers['x-api-key']).toBe('anthropic-key-xyz');
      expect(received.headers['anthropic-version']).toBe('2023-06-01');

      // Metering: the agent's budgets.tokensUsed must actually have
      // increased by the reported token count (40 + 60 = 100), proving
      // metering is wired end-to-end, not just parsed.
      const [budgetAfter] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
      expect(budgetAfter.tokensUsed - budgetBefore.tokensUsed).toBe(100);

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('allows via openai style with a Bearer auth header', async () => {
    const { db, sql } = getDb(cfg);
    const openaiUpstream = await startUpstream({ total_tokens: 77 });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llm-oa-${Date.now()}`, tenant: 'test', allowedModels: ['gpt-4'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:openai', 'openai-key-abc', `http://127.0.0.1:${openaiUpstream.port}/v1/chat/completions`);
      const app = buildServer({ cfg, db, engine });

      const res = await app.inject({
        method: 'POST',
        url: '/llm/gpt-4',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'complete', payload: {}, upstreamStyle: 'openai' },
      });

      expect(res.statusCode).toBe(200);
      expect(openaiUpstream.requests.length).toBe(1);
      expect(openaiUpstream.requests[0].headers['authorization']).toBe('Bearer openai-key-abc');

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => openaiUpstream.server.close(r));
    }
  });

  it('denies a non-allowlisted model with 403 and makes zero upstream requests', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llm-deny-${Date.now()}`, tenant: 'test', allowedModels: ['claude-sonnet-5'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:openai', 'openai-key-abc', `http://127.0.0.1:${upstream.port}/v1/x`);
      const app = buildServer({ cfg, db, engine });

      const before = upstream.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/llm/gpt-4',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'complete', payload: {}, upstreamStyle: 'openai' },
      });

      expect(res.statusCode).toBe(403);
      expect(upstream.requests.length).toBe(before);

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('denies when the budget is exhausted even for an allowed model (fail-closed cut-off)', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llm-budget-${Date.now()}`, tenant: 'test', allowedModels: ['claude-sonnet-5'] });
      await seedBudget(db, agent.id, 0, 0); // zero budget
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}/v1/messages`);
      const app = buildServer({ cfg, db, engine });

      const before = upstream.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/llm/claude-sonnet-5',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'complete', payload: {}, upstreamStyle: 'anthropic' },
      });

      expect(res.statusCode).toBe(403);
      expect(upstream.requests.length).toBe(before);

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('SECURITY: ignores a caller-supplied upstreamUrl and never contacts the attacker-controlled server', async () => {
    const { db, sql } = getDb(cfg);
    let attacker: Awaited<ReturnType<typeof startUpstream>> | undefined;
    try {
      attacker = await startUpstream({ input_tokens: 1, output_tokens: 1 });
      const { agent, apiKey } = await registerAgent(db, { name: `llm-exfil-${Date.now()}`, tenant: 'test', allowedModels: ['claude-sonnet-5'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // Register the credential against the LEGITIMATE upstream only.
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}/v1/messages`);
      const app = buildServer({ cfg, db, engine });

      const beforeLegit = upstream.requests.length;
      const beforeAttacker = attacker.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/llm/claude-sonnet-5',
        headers: { 'x-api-key': apiKey },
        payload: {
          operation: 'complete',
          payload: { messages: [] },
          upstreamStyle: 'anthropic',
          // Attacker-controlled caller still tries to redirect the credential.
          upstreamUrl: `http://127.0.0.1:${attacker.port}/v1/messages`,
        },
      });

      expect(res.statusCode).toBe(200);
      // The attacker server must receive ZERO requests.
      expect(attacker.requests.length).toBe(beforeAttacker);
      // The legitimate, operator-registered upstream received exactly one request.
      expect(upstream.requests.length).toBe(beforeLegit + 1);
      const received = upstream.requests[upstream.requests.length - 1];
      expect(received.headers['x-api-key']).toBe('anthropic-key-xyz');

      await app.close();
    } finally {
      await sql.end();
      if (attacker) await new Promise((r) => attacker!.server.close(r));
    }
  });

  it('SECURITY REGRESSION: a caller-injected payload.model cannot override the policy-gated URL model, and the audit record reflects the model that actually ran', async () => {
    const { db, sql } = getDb(cfg);
    try {
      // Allowlisted for claude-sonnet-5 ONLY.
      const { agent, apiKey } = await registerAgent(db, { name: `llm-modeloverride-${Date.now()}`, tenant: 'test', allowedModels: ['claude-sonnet-5'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${upstream.port}/v1/messages`);
      const app = buildServer({ cfg, db, engine });

      const correlationId = randomUUID();
      const before = upstream.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/llm/claude-sonnet-5',
        headers: { 'x-api-key': apiKey, 'x-correlation-id': correlationId },
        payload: {
          operation: 'complete',
          upstreamStyle: 'anthropic',
          // Attacker-controlled payload attempts to smuggle a DIFFERENT
          // model past OPA's allowlist check (which only ever sees the URL
          // model) and have the gateway actually run it.
          payload: { model: 'claude-opus-4-8', messages: [] },
        },
      });

      expect(res.statusCode).toBe(200);
      expect(upstream.requests.length).toBe(before + 1);
      const received = upstream.requests[upstream.requests.length - 1];
      // The upstream must have received the ALLOWLISTED URL model, never the
      // caller's injected one — this is the regression guard for the whole
      // spread-order bug.
      expect((received.body as { model?: unknown }).model).toBe('claude-sonnet-5');
      expect((received.body as { model?: unknown }).model).not.toBe('claude-opus-4-8');

      // Audit truthfulness: the record written for this exact request must
      // name the model that actually ran (the allowlisted one), proving the
      // audit spine did not get to falsify what happened.
      const [record] = await db
        .select()
        .from(auditRecords)
        .where(dsql`${auditRecords.whenWhere}->>'correlationId' = ${correlationId}`)
        .limit(1);
      expect(record).toBeDefined();
      expect(record.verdict).toBe('allow');
      expect((record.what as { target?: unknown }).target).toBe('llm:claude-sonnet-5');
      expect((record.what as { target?: unknown }).target).not.toBe('llm:claude-opus-4-8');

      await app.close();
    } finally {
      await sql.end();
    }
  });

  it('SECURITY: does not follow a redirect from the registered upstream and makes zero requests to the redirect target', async () => {
    const { db, sql } = getDb(cfg);
    let attacker: Awaited<ReturnType<typeof startUpstream>> | undefined;
    let redirector: Server | undefined;
    try {
      attacker = await startUpstream();
      // Ephemeral "registered" upstream that always responds 302 pointing at
      // the attacker server — simulating a compromised registered upstream
      // trying to hop the mediated call (and its injected credential) to a
      // host the operator never authorized.
      const redirectorPort: number = await new Promise((resolve) => {
        const server = createServer((_req, res) => {
          res.writeHead(302, { location: `http://127.0.0.1:${attacker!.port}/v1/messages` });
          res.end();
        });
        redirector = server;
        server.listen(0, '127.0.0.1', () => {
          const addr = server.address();
          resolve(typeof addr === 'object' && addr ? addr.port : 0);
        });
      });

      const { agent, apiKey } = await registerAgent(db, { name: `llm-redirect-${Date.now()}`, tenant: 'test', allowedModels: ['claude-sonnet-5'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      // Register the credential against the redirecting upstream.
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${redirectorPort}/v1/messages`);
      const app = buildServer({ cfg, db, engine });

      const beforeAttacker = attacker.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/llm/claude-sonnet-5',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'complete', payload: { messages: [] }, upstreamStyle: 'anthropic' },
      });

      // Fail-closed: the redirect must be treated as an upstream failure, not
      // silently followed.
      expect(res.statusCode).toBe(403);
      // The attacker server must receive ZERO requests — this locks the
      // behaviour in our own code (redirect: 'manual' + explicit rejection)
      // rather than relying on undici's incidental Authorization-stripping.
      expect(attacker.requests.length).toBe(beforeAttacker);

      await app.close();
    } finally {
      await sql.end();
      if (attacker) await new Promise((r) => attacker!.server.close(r));
      if (redirector) await new Promise((r) => redirector!.close(r));
    }
  });

  it('does not inflate the meter when upstream returns usage counts as strings (numeric guard)', async () => {
    const { db, sql } = getDb(cfg);
    const stringUsageUpstream = await startUpstream({ input_tokens: '40' as unknown as number, output_tokens: 60 });
    try {
      const { agent, apiKey } = await registerAgent(db, { name: `llm-strusage-${Date.now()}`, tenant: 'test', allowedModels: ['claude-sonnet-5'] });
      await seedBudget(db, agent.id, 1_000_000, 1_000_000);
      await putCredential(db, cfg, agent.id, 'llm:anthropic', 'anthropic-key-xyz', `http://127.0.0.1:${stringUsageUpstream.port}/v1/messages`);
      const app = buildServer({ cfg, db, engine });

      const [budgetBefore] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);

      const res = await app.inject({
        method: 'POST',
        url: '/llm/claude-sonnet-5',
        headers: { 'x-api-key': apiKey },
        payload: { operation: 'complete', payload: { messages: [] }, upstreamStyle: 'anthropic' },
      });

      expect(res.statusCode).toBe(200);
      const [budgetAfter] = await db.select().from(budgets).where(eq(budgets.agentId, agent.id)).limit(1);
      // With the naive `+` bug, "40" + 60 === "4060" (string), which would
      // either blow up the numeric column or record 4060. The coerced,
      // correct delta is 40 + 60 = 100.
      const delta = budgetAfter.tokensUsed - budgetBefore.tokensUsed;
      expect(delta).toBe(100);
      expect(delta).not.toBe(4060);

      await app.close();
    } finally {
      await sql.end();
      await new Promise((r) => stringUsageUpstream.server.close(r));
    }
  });

  it('rejects an unauthenticated request with 403 and makes zero upstream requests', async () => {
    const { db, sql } = getDb(cfg);
    try {
      const app = buildServer({ cfg, db, engine });
      const before = upstream.requests.length;
      const res = await app.inject({
        method: 'POST',
        url: '/llm/claude-sonnet-5',
        payload: { operation: 'complete', payload: {}, upstreamStyle: 'anthropic' },
      });
      expect(res.statusCode).toBe(403);
      expect(upstream.requests.length).toBe(before);
      await app.close();
    } finally {
      await sql.end();
    }
  });
});
