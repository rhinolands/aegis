import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { eq } from 'drizzle-orm';
import type { ServerDeps } from '../server.js';
import { authenticate, AuthError } from '../auth/authenticate.js';
import { agents } from '../db/schema.js';
import { getCredentialTarget } from '../credentials/store.js';
import { governPreflight, governSettle, type GovernContext, type GovernDeps } from '../pipeline/govern.js';
import { extractUsage, priceMicros } from '../pricing/models.js';
import { makeUsageTee, type StreamUsage } from '../streaming/sse-usage-tee.js';
import { log } from '../log.js';

// ---------------------------------------------------------------------------
// G1 — the anthropic-compat raw passthrough route (POST /v1/messages).
//
// WHERE THE REQUEST GOES IS NOT NEGOTIABLE BY THE CALLER.
// The upstream destination is deliberately NOT part of any schema on this
// route and is never read from the request — same reasoning as the MCP plane
// (src/planes/mcp.ts), the A2A plane (src/planes/a2a.ts) and the envelope LLM
// plane (src/planes/llm.ts). Accepting a caller-supplied destination and then
// attaching the gateway's scoped upstream API key to it is a
// credential-exfiltration primitive: an authenticated agent allowlisted for a
// model could otherwise point the request at a server it controls and receive
// the injected key. The destination is always resolved server-side from the
// operator-registered scoped_credentials row for (agentId, 'llm:anthropic'),
// together with the secret, in one lookup. The body of this route is
// Anthropic's own Messages request and passes through untouched, so a stray
// top-level field naming a URL is simply never read — there is no code path
// on this route that can turn a body value into a destination.
//
// WHY THIS IS NOT A FOURTH PLANE.
// This is a protocol proxy that happens to govern, not another envelope
// plane. It therefore does NOT use the pass/deny binary of the pipeline
// wrapper in src/pipeline/govern.ts: that wrapper's execute() contract can
// only succeed or throw, and every throw becomes a 403. Correct for the
// envelope planes; wrong here, because an Anthropic 400/401/429/5xx must
// reach the caller as ITS OWN status so the SDK raises the right typed error
// and its retry machinery still works. This route takes the authorization
// decision up front with governPreflight, relays the upstream verbatim, and
// meters afterwards with governSettle.
//
// THE ENVELOPE ROUTE IS DELIBERATELY LEFT UNTOUCHED. src/planes/llm.ts keeps
// its strict body schema and its `{...payload, model, operation}` spread
// order: both are load-bearing anti-bypass measures for THAT route (a caller
// -supplied payload.model must never win over the policy-gated model). Do not
// soften them, and do not imitate them here — this route never merges
// anything into the caller's body, so it has no spread-order hazard to guard.
// ---------------------------------------------------------------------------

/** The operation name recorded in the audit trail and handed to OPA. The allowlist check keys off `request.model`, not this. */
const OPERATION = 'messages.create';

/**
 * Generic, Acme-safe refusal copy. Deliberately says nothing about WHICH
 * control refused — that distinction travels in the machine-readable code
 * below, never in prose a user might read.
 */
const DENIAL_MESSAGE = 'Request denied by the governance gateway.';

/**
 * The published gateway_code vocabulary (D-09). This is a CONTRACT with Acme:
 * Acme switches on `err.error.error.gateway_code` and renders its own copy.
 *
 * The streaming-refusal member is deliberately RETAINED after plan 45-07 (G2)
 * replaced plan 45-05's P-06 refusal with the real passthrough. No code path
 * emits it on the normal streaming flow any more, but the published vocabulary
 * is a contract Acme already switches on, and a future path that has to refuse
 * a streamed body (an upstream style that cannot stream, a kill switch) should
 * still have a defined, Acme-safe way to say so rather than inventing one.
 */
type GatewayCode =
  | 'model_not_allowed'
  | 'budget_exhausted'
  | 'not_provisioned'
  | 'rate_limited'
  | 'unknown_denial'
  | 'invalid_request'
  | 'streaming_not_supported'
  | 'upstream_redirect'
  | 'upstream_unreachable';

/**
 * Maps Aegis's INTERNAL deny reason onto the published gateway_code.
 *
 *   deny-by-default / policy denied  -> model_not_allowed
 *   token budget exceeded            -> budget_exhausted
 *   cost budget exceeded             -> budget_exhausted
 *   no budget configured             -> not_provisioned
 *   rate limit exceeded              -> rate_limited
 *   anything else                    -> unknown_denial
 *
 * D-09 RULE: Aegis's internal vocabulary must NEVER appear in the response.
 * The Anthropic SDK stuffs the whole error body into `err.message` when the
 * body has no top-level `message` field (core/error.js:18-35), and Acme
 * renders that string into user-facing copy — so a raw 'deny-by-default'
 * would land in front of a customer. That is why this is one explicit,
 * exhaustive function with an unknown_denial default, and not a string match
 * sprinkled through the handler: a new internal reason degrades to a safe
 * generic code instead of leaking.
 */
function denialGatewayCode(reason: string): GatewayCode {
  switch (reason) {
    case 'deny-by-default':
    case 'policy denied':
      return 'model_not_allowed';
    case 'token budget exceeded':
    case 'cost budget exceeded':
    case 'budget exceeded':
      return 'budget_exhausted';
    case 'no budget configured':
      return 'not_provisioned';
    case 'rate limit exceeded':
      return 'rate_limited';
    default:
      return 'unknown_denial';
  }
}

/**
 * An Anthropic-shaped error envelope. `error.type` is what the SDK surfaces as
 * `err.type` (it reads body.error.type — a NESTED lookup), and the extra
 * gateway_code field rides along in `err.error` verbatim.
 */
function anthropicError(type: string, message: string, code: GatewayCode): unknown {
  return { type: 'error', error: { type, message, gateway_code: code } };
}

/**
 * Upstream request headers are built from an ALLOWLIST, never a blocklist.
 *
 * src/auth/authenticate.ts accepts BOTH `x-api-key` and a Bearer JWT, so a
 * blocklist that merely stripped `x-api-key` would forward a caller's
 * `Authorization` header straight to Anthropic. Explicitly NOT copied:
 * authorization, host, content-length, connection, transfer-encoding.
 *
 * `anthropic-beta` is load-bearing (kill-finding K2): the SDK strips `betas`
 * out of the request body and into that header, so it is the ONLY carrier of
 * the beta signal. Dropping it silently changes structured-output behaviour
 * for beta.messages.parse().
 */
const FORWARDED_HEADERS = ['anthropic-version', 'anthropic-beta', 'content-type', 'accept'] as const;

function buildUpstreamHeaders(inbound: FastifyRequest['headers'], secret: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of FORWARDED_HEADERS) {
    const value = inbound[name];
    if (typeof value === 'string' && value.length > 0) out[name] = value;
  }
  // x-stainless-* is SDK telemetry; forwarding it is harmless and helps
  // Anthropic-side triage.
  for (const [name, value] of Object.entries(inbound)) {
    if (name.startsWith('x-stainless-') && typeof value === 'string') out[name] = value;
  }
  if (!out['content-type']) out['content-type'] = 'application/json';
  // The gateway injects the operator-registered secret. The calling agent
  // never holds it — it only ever presents its own gateway-issued key.
  out['x-api-key'] = secret;
  return out;
}

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * The exact JSON bytes the caller sent, captured by this route's
     * encapsulated content-type parser. Forwarded verbatim so no field can be
     * added, removed or reordered on the way to Anthropic.
     */
    rawLlmBody?: string;
  }
}

export function registerLlmRawPlane(app: FastifyInstance, deps: ServerDeps): void {
  // Registered inside a plugin scope so the content-type parser below is
  // ENCAPSULATED (fastify/lib/plugin-override.js rebuilds the parser per
  // scope) and the other three planes keep Fastify's stock JSON parsing.
  // No `await` before the route is declared — see Fastify's ContentTypeParser
  // docs, "Using addContentTypeParser with fastify.register".
  app.register((scope, _opts, done) => {
    scope.addContentTypeParser('application/json', { parseAs: 'string' }, (req, body, doneParse) => {
      req.rawLlmBody = body as string;
      try {
        doneParse(null, JSON.parse(body as string));
      } catch {
        const err = new Error('request body is not valid JSON') as Error & { statusCode?: number };
        err.statusCode = 400;
        doneParse(err, undefined);
      }
    });

    // One Fastify route serves BOTH /v1/messages and /v1/messages?beta=true:
    // a query string does not affect route matching. req.query.beta is read
    // only to decide whether to append it upstream, never to reject a request
    // for its absence — the advisor lane never sends it.
    //
    // P-08: 8 MiB, a per-ROUTE option (Fastify's route bodyLimit overrides the
    // parser's — lib/route.js:382). Fastify's default is 1 MiB, and Acme's
    // assessment sends the WAF prompt plus the full blueprint JSON plus the
    // cost table plus the ALZ findings in one content string; a 413 there
    // would look like a gateway bug. Still bounded, deliberately.
    scope.post('/v1/messages', { bodyLimit: 8388608 }, handler);
    done();
  });

  async function handler(req: FastifyRequest, reply: FastifyReply): Promise<unknown> {
    const { db, cfg, engine } = deps;
    const govDeps: GovernDeps = { db, cfg, engine };

    // 1. Identity comes ONLY from the presented credential — never from the body.
    let principal;
    try {
      principal = await authenticate(db, cfg, req);
    } catch (e) {
      if (e instanceof AuthError) return reply.code(403).send({ error: 'unauthenticated' });
      throw e;
    }

    // 2. Permissive validation. The body is Anthropic's own Messages request
    //    and must pass through untouched, so nothing beyond `model` is
    //    schema-checked. The model is validated by OPA against the agent's
    //    allowlist, not by a schema — which is the correct control here: a
    //    schema could only ever restate a static shape, while the allowlist is
    //    per-agent operator policy.
    const body = req.body;
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      return reply.code(400).send(anthropicError('invalid_request_error', 'Request body must be a JSON object.', 'invalid_request'));
    }
    const model = (body as { model?: unknown }).model;
    if (typeof model !== 'string' || model.length === 0) {
      return reply.code(400).send(anthropicError('invalid_request_error', 'Request body must carry a non-empty "model".', 'invalid_request'));
    }

    const [agent] = await db.select().from(agents).where(eq(agents.id, principal.agentId)).limit(1);
    if (!agent) return reply.code(403).send({ error: 'unknown agent' });

    // 3. Authorization, taken BEFORE the first upstream byte.
    const ctx: GovernContext = {
      principal,
      agent,
      plane: 'llm',
      request: { model, operation: OPERATION },
      target: `llm:${model}`,
      correlationId: (req.headers['x-correlation-id'] as string) ?? randomUUID(),
      origin: req.ip,
      args: body,
    };

    const pre = await governPreflight(govDeps, ctx);
    if (!pre.allow) {
      // P-07: an Aegis denial stays 403 even for the rate limiter. The limiter
      // is a hard per-agent cap, so a retry cannot change the outcome; the
      // explicit header keeps that property even if the status ever changes.
      reply.header('x-should-retry', 'false');
      return reply.code(403).send(anthropicError('permission_error', DENIAL_MESSAGE, denialGatewayCode(pre.reason)));
    }
    const decision = pre.decision;

    // 4. Credential AND destination in ONE lookup. Never getCredentialSecret
    //    -only: pairing that secret with any otherwise-sourced URL recreates
    //    the exfiltration primitive this codebase already fixed once (see the
    //    nine-line warning on the secret-only accessor in
    //    src/credentials/store.ts).
    //
    //    GUARDED, for the same reason as the fetch rejection below (CR-03a).
    //    governPreflight has ALREADY allowed and has written NOTHING — a
    //    preflight allow writes no record; only governSettle does. So a DB blip,
    //    a pool exhaustion or a credential-decrypt fault (corruption at rest, a
    //    rotated master key) thrown from here used to escape the handler as a
    //    Fastify 500 with NO AUDIT ROW AT ALL for a request the gateway
    //    authorized. Settle first, then log, then respond — the house pattern of
    //    the two guards further down.
    let registered: Awaited<ReturnType<typeof getCredentialTarget>>;
    try {
      registered = await getCredentialTarget(db, cfg, principal.agentId, 'llm:anthropic');
    } catch (err) {
      await governSettle(govDeps, ctx, decision, { tokens: 0, costMicros: 0, error: 'credential_lookup_failed' });
      log.error({ err, agentId: principal.agentId }, 'llm-raw: credential lookup failed after authorization — no upstream destination could be resolved');
      reply.header('x-should-retry', 'false');
      return reply
        .code(502)
        .send(anthropicError('api_error', 'The gateway could not resolve an upstream destination.', 'not_provisioned'));
    }
    // A successful lookup that returns nothing is a DIFFERENT condition — the
    // operator never registered a destination — and it already settles
    // correctly below. Deliberately left as it was.
    if (!registered || !registered.upstreamUrl) {
      // Fail closed: there is nowhere authorized to send this request.
      await governSettle(govDeps, ctx, decision, { tokens: 0, costMicros: 0, error: 'not_provisioned' });
      reply.header('x-should-retry', 'false');
      return reply
        .code(403)
        .send(anthropicError('permission_error', DENIAL_MESSAGE, 'not_provisioned'));
    }

    // 5. The registered upstream_url is a bare ORIGIN (unlike the envelope
    //    route, which POSTs to it as-is), so the path is concatenated here.
    const base = registered.upstreamUrl.replace(/\/+$/, '');
    const wantsBeta = (req.query as { beta?: unknown } | undefined)?.beta !== undefined;
    const target = `${base}/v1/messages${wantsBeta ? '?beta=true' : ''}`;

    const headers = buildUpstreamHeaders(req.headers, registered.secret);
    // Forward the caller's exact bytes. Re-serializing the parsed object would
    // risk key reordering; the fallback adds NOTHING.
    const outboundBody = req.rawLlmBody ?? JSON.stringify(body);

    // Manual redirect handling plus the explicit 3xx rejection below: a
    // mediated call must terminate at the operator-registered destination and
    // must never be silently redirected elsewhere. Node 22's undici happens to
    // strip auth headers on a cross-origin redirect, but that is runtime
    // behaviour we do not control and must not rely on — this asserts the
    // safety property in our own code instead.
    let upstream: Response;
    try {
      upstream = await fetch(target, { method: 'POST', headers, body: outboundBody, redirect: 'manual' });
    } catch (err) {
      // The call was authorized and attempted but never reached anyone. Audit
      // it rather than letting the rejection escape as an unaudited 500.
      await governSettle(govDeps, ctx, decision, { tokens: 0, costMicros: 0, error: 'upstream_unreachable' });
      log.error({ err, agentId: principal.agentId }, 'llm-raw: upstream request failed before a response was received');
      return reply
        .code(502)
        .send(anthropicError('api_error', 'The upstream model provider could not be reached.', 'upstream_unreachable'));
    }

    if (upstream.status >= 300 && upstream.status < 400) {
      await governSettle(govDeps, ctx, decision, { tokens: 0, costMicros: 0, error: 'upstream_redirect' });
      // Do not follow it, and do not surface the Location value.
      return reply
        .code(502)
        .send(anthropicError('api_error', 'The upstream model provider attempted a redirect, which is refused.', 'upstream_redirect'));
    }

    // The upstream request id is the join key Phase 47's audit correlation
    // will want between an Acme-side record and the real Anthropic call.
    const requestId = upstream.headers.get('request-id');
    if (requestId) reply.header('request-id', requestId);

    // Read once, here, so the streaming branch below and the SSE writeHead that
    // follows it agree about what the upstream actually sent. A substring check,
    // not equality: the header routinely carries parameters
    // (`text/event-stream; charset=utf-8`).
    const upstreamContentType = upstream.headers.get('content-type') ?? '';
    const upstreamIsEventStream = upstreamContentType.includes('text/event-stream');

    // ---------------------------------------------------------------------
    // 6. G2 — SSE PASSTHROUGH.
    //
    // WHY BOTH BRANCHES SHARE THE ONE fetch ABOVE, AND WHY THE STATUS IS
    // CHECKED BEFORE A SINGLE BYTE IS WRITTEN.
    // Once the first byte of an SSE response is on the wire the HTTP status is
    // fixed, and the caller's SDK cannot recover from a late failure:
    // finalMessage() throws `request ended without sending any chunks` if the
    // stream produced nothing (lib/MessageStream.js:429-431) and
    // `Unexpected event order, got X before "message_start"` if the first event
    // is not message_start (:442-443). An SSE `error` event mid-stream is no
    // escape hatch either — it reaches the SDK as an UNTYPED APIError with
    // status undefined (core/streaming.js:113-118), so it can carry no typed
    // denial. A gateway that opens an SSE response and THEN fails therefore
    // produces an opaque, unclassifiable Acme-side error.
    //
    // So the ordering is structural, not stylistic: governPreflight has already
    // run, the credential is already resolved, the upstream has already
    // answered, and its status has already been inspected (the 3xx branch
    // above, and `upstream.ok` here). A non-2xx or body-less upstream on a
    // streaming request falls through to the SAME Pattern-3 buffered relay the
    // non-streaming branch uses — real status, real bytes, no half-opened
    // stream. A mid-stream deny is not merely avoided here; it is made
    // structurally impossible.
    //
    // AND THE RESPONSE MUST ACTUALLY BE AN EVENT STREAM (WR-04). The condition
    // used to ask only what the CALLER requested. But this branch meters from
    // SSE frames, so a 2xx body that is not an event stream — an upstream that
    // ignores `stream`, a caching proxy that buffers it, a future compatibility
    // mode — produces no message_start and no message_delta, the usage
    // accumulator stays at zero, and the turn settles `allow` with tokens 0,
    // costMicros 0 AND NO ERROR MARKER: a fully-billed call metered at zero that
    // looks in the audit trail exactly like a clean, cheap one. That is the same
    // vacuous-cap failure mode `priced: false` exists to make loud, arriving by
    // a different door.
    //
    // The narrowing follows the reasoning above rather than contradicting it:
    // the point of checking everything before the first byte is that a
    // half-opened SSE response cannot be recovered from. A response that is not
    // an event stream simply falls through to the SAME Pattern-3 buffered relay
    // as a non-2xx one — real status, real bytes, and metered from the body.
    // Deliberately NOT a refusal and NOT a new gateway_code: the caller gets the
    // upstream's own answer, which is what this route exists to deliver.
    // ---------------------------------------------------------------------
    if ((body as { stream?: unknown }).stream === true && upstream.ok && upstream.body !== null && upstreamIsEventStream) {
      const usage: StreamUsage = { input: 0, output: 0, cacheWrite: 0, cacheRead: 0, cacheWrite1h: 0 };

      // SINGLE-SHOT SETTLE. A client abort racing the pipeline's rejection would
      // otherwise meter the same turn twice. The promise is assigned before the
      // first `await` inside it, so the guard cannot itself be raced, and later
      // callers await the SAME in-flight settle rather than starting a second.
      let settled: Promise<void> | null = null;
      const settleOnce = (error?: string): Promise<void> => {
        if (settled) return settled;
        settled = (async () => {
          // ALL FOUR CLASSES ANTHROPIC BILLS, priced at their own rates and
          // each rounded as its own line item (src/pricing/models.ts).
          //
          // The tee has ALWAYS collected cacheWrite/cacheRead — its own header
          // called costing cached tokens at the wrong rate "a silent-money bug"
          // — and this call site then threw them away, which was that exact bug
          // (CR-02). usage.input_tokens EXCLUDES both cache classes, so a
          // 200K-token prompt sent with cache_control reports ~20 input tokens
          // against roughly $0.75 of real spend. On a passthrough route that
          // forwards the caller's body verbatim and validates nothing but
          // `model`, any authenticated caller can produce that shape.
          const { costMicros, priced } = priceMicros(model, usage.input, usage.output, usage.cacheWrite, usage.cacheRead, usage.cacheWrite1h);
          if (!priced) {
            log.error(
              { model, agentId: principal.agentId },
              'unpriced_model: allowlisted model has no MODEL_PRICES entry — cost metered as 0',
            );
          }
          // THE ROADMAP G2 RULE, now citation-grounded by the block above:
          // bytes already delivered means the audit verdict stays `allow` with
          // whatever usage was accumulated plus an error marker — NEVER a
          // retroactive 403. Metering is attached to pipeline COMPLETION, not
          // to sighting message_stop, so a normal end, an upstream fault and a
          // closed tab all settle (RESEARCH Pitfall 9: closing the tab must not
          // be a way to get free tokens).
          const res = await governSettle(govDeps, ctx, decision, {
            // The TOKEN cap counts all five classes too, for the same reason the
            // cost cap does: a cap that ignores the classes a caller can inflate
            // at will is not a cap. cacheWrite1h is included so a 1h write is not
            // silently dropped from the token count (when the breakdown is
            // present cacheWrite+cacheWrite1h sum to the old flat total — DEBT-05).
            tokens: usage.input + usage.output + usage.cacheWrite + usage.cacheWrite1h + usage.cacheRead,
            costMicros,
            error,
          });
          if (!res.ok) {
            log.error(
              { agentId: principal.agentId, correlationId: ctx.correlationId },
              'llm-raw: streamed turn executed but could not be settled; record only recoverable from this log line',
            );
          }
        })();
        return settled;
      };

      // Acme's own advisor route writes this exact header set before relaying
      // SSE to the browser (apps/api/src/routes/blueprints/advisor.ts), and the
      // relayed stream travels the same path. The accel-buffering header tells
      // an intermediary proxy not to hold the stream back, which would destroy
      // the token-by-token rendering the advisor lane exists for.
      reply.raw.writeHead(200, {
        'content-type': upstream.headers.get('content-type') ?? 'text/event-stream',
        'cache-control': 'no-cache',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
        ...(requestId ? { 'request-id': requestId } : {}),
      });
      reply.hijack();

      // A response that emits `close` before it finished writing IS the client
      // disconnect. Fire-and-forget is safe because settleOnce is idempotent and
      // the catch below awaits the same promise.
      reply.raw.on('close', () => {
        if (!reply.raw.writableFinished) void settleOnce('client_disconnected');
      });

      const tee = makeUsageTee((u) => { Object.assign(usage, u); });
      try {
        // WHY pipeline AND NOT A BARE PIPE CHAIN: it destroys BOTH ends on
        // failure and propagates backpressure and errors natively, so a slow
        // client throttles the upstream read instead of growing a buffer, and a
        // dead upstream tears the client response down instead of hanging it
        // open. A bare pipe leaks the loser of either race.
        await pipeline(Readable.fromWeb(upstream.body as WebReadableStream<Uint8Array>), tee, reply.raw);
        await settleOnce();
      } catch (err) {
        log.error({ err, agentId: principal.agentId }, 'llm-raw: SSE relay ended abnormally');
        await settleOnce(err instanceof Error ? err.message : String(err));
        reply.raw.destroy();
      }
      return reply;
    }

    // 7. Buffered relay. Read the bytes, never a parsed object: a non-JSON
    // upstream body (an HTML error page from an intercepting proxy, an empty
    // 502) must be relayed as it stands, not silently rewritten into {}.
    //
    // GUARDED (CR-03b). A connection reset mid-body, a Content-Length mismatch
    // or a decompression error rejects HERE, after the headers arrived. This
    // differs from the fetch rejection above in one material way: there, the
    // call never reached anyone; here, THE UPSTREAM HAS ALREADY PRODUCED AND
    // WILL BILL THE COMPLETION. Unguarded, that combination is the worst one
    // available — real money spent, unaudited 500 returned, no trace of the call.
    // Aegis meters ZERO rather than inventing a figure: it has no usage numbers
    // at all, and an honest zero carrying a marker is recoverable from the audit
    // trail, whereas a guessed number is a lie in the meter. This is the same
    // disposition the relayed-failure and non-JSON branches below already take.
    let text: string;
    try {
      text = await upstream.text();
    } catch (err) {
      await governSettle(govDeps, ctx, decision, { tokens: 0, costMicros: 0, error: 'upstream_body_read_failed' });
      log.error({ err, agentId: principal.agentId }, 'llm-raw: upstream response body could not be read after headers arrived — the completion was produced and will be billed');
      return reply
        .code(502)
        .send(anthropicError('api_error', 'The upstream model provider response could not be read.', 'upstream_unreachable'));
    }

    if (!upstream.ok) {
      // PATTERN 3 — the whole point of this route. Relay Anthropic's own
      // status and body so the SDK raises the right typed error class and its
      // retry policy still applies. Four cases the envelope route collapses
      // into 403 today: 400 (bad request, message destroyed), 401 (the
      // gateway's own key is bad — an OPERATOR problem, not a policy deny),
      // 429 (403 is not retryable, so the SDK's whole retry + retry-after
      // machinery is defeated) and 5xx (a transient blip becomes a hard
      // user-visible refusal). The decision still stands, so this settles as
      // an allow carrying an error marker, metering zero.
      await governSettle(govDeps, ctx, decision, { tokens: 0, costMicros: 0, error: `upstream_${upstream.status}` });
      return reply.code(upstream.status).type('application/json').send(text);
    }

    // Parse for USAGE only, and guard it: a 2xx that is not JSON still relays,
    // metering zero with a marker rather than throwing away a good response.
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      const settledNonJson = await governSettle(govDeps, ctx, decision, { tokens: 0, costMicros: 0, error: 'upstream_non_json_body' });
      if (!settledNonJson.ok) return reply.code(settledNonJson.status).send(settledNonJson.body);
      return reply.code(upstream.status).type('application/json').send(text);
    }

    // ALL FOUR CLASSES, same as the streaming settle above. Anthropic bills
    // input, output, cache-creation and cache-read as separate line items at
    // their own rates, and `usage.input_tokens` excludes both cache classes —
    // so pricing input+output alone does not under-meter a cached call
    // slightly, it misses almost all of it (CR-02). This branch was worse than
    // the streaming one before plan 45-12: extractUsage did not even READ the
    // cache fields.
    const { input, output, cacheWrite, cacheRead, cacheWrite1h } = extractUsage('anthropic', parsed);
    const { costMicros, priced } = priceMicros(model, input, output, cacheWrite, cacheRead, cacheWrite1h);
    if (!priced) {
      // Error level, not debug and not a silent zero — same signal the
      // envelope plane emits. A model that policy allowlisted but the price
      // table does not know meters $0 forever, which makes a cost cap vacuous
      // while looking like it works.
      log.error(
        { model, agentId: principal.agentId },
        'unpriced_model: allowlisted model has no MODEL_PRICES entry — cost metered as 0',
      );
    }

    const settled = await governSettle(govDeps, ctx, decision, {
      tokens: input + output + cacheWrite + cacheWrite1h + cacheRead,
      costMicros,
    });
    if (!settled.ok) return reply.code(settled.status).send(settled.body);

    return reply.code(upstream.status).type('application/json').send(text);
  }
}
