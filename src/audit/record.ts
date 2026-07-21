import { createHash } from 'node:crypto';

export interface IdentityChain { agent: string; onBehalfOf: string[] }
export interface AuditWho { agentId: string; identity: IdentityChain }
export interface AuditWhat { target: string; operation: string; argsDigest: string }
export interface AuditWhenWhere { origin: string; correlationId: string }
export interface AuditWhy { reason: string; approval?: { by: string; granted: boolean } }

export interface AuditRecord {
  id: string;
  ts: string;                 // ISO 8601
  tenant: string;
  plane: 'mcp' | 'a2a' | 'llm' | 'approval';
  who: AuditWho;
  what: AuditWhat;
  whenWhere: AuditWhenWhere;
  why: AuditWhy;
  verdict: 'allow' | 'deny';
  policyVersion: string;
  subjectKeyId: string | null;
}

// Deterministic JSON with recursively sorted keys — the hashed representation.
//
// MUST be total: it feeds argsDigest() and the audit hash chain (chain.ts), both of
// which are called from paths that must never throw (see govern.ts). A throw here
// after an upstream action has already executed turns a successful request into an
// unhandled rejection with no audit trail — the exact bug this function closes.
//
// Values that plain JSON.stringify cannot represent are replaced with a deterministic,
// clearly-tagged stand-in *before* being handed to JSON.stringify, so JSON.stringify
// itself never sees them and never throws:
//   - BigInt            -> { $type: 'bigint', value: <decimal string> }
//   - function          -> { $type: 'function', value: <name or '<anonymous>'> }
//   - symbol            -> { $type: 'symbol', value: <description or ''> }
//   - circular reference -> the string '[Circular]' at the point of recurrence
//
// Anything that already serialized successfully before this change (plain objects,
// arrays, strings, numbers, booleans, null, undefined-as-omitted-key/array-null,
// NaN/Infinity-as-null) takes the exact same code path as before (recursive key sort,
// same array mapping) and therefore produces byte-identical output — existing audit
// hashes remain valid. See test/audit-record.test.ts for a pinned regression string.
export function canonical(value: unknown): string {
  const json = JSON.stringify(normalize(value, new WeakSet<object>()));
  // JSON.stringify(x) returns the *JS value* undefined (not the string "undefined")
  // for a small set of top-level inputs (bare undefined, bare function, bare symbol).
  // normalize() already retags function/symbol so this can only fire for bare
  // top-level `undefined`, which never validly hashed before either — pin it to a
  // stable literal instead of returning a non-string from a function typed to return
  // string (and instead of letting downstream createHash().update(undefined) throw).
  return json === undefined ? 'null' : json;
}

function normalize(v: unknown, seen: WeakSet<object>): unknown {
  const t = typeof v;
  if (t === 'bigint') return { $type: 'bigint', value: (v as bigint).toString() };
  if (t === 'function') return { $type: 'function', value: (v as { name?: string }).name || '<anonymous>' };
  if (t === 'symbol') return { $type: 'symbol', value: (v as symbol).description ?? '' };
  if (t !== 'object' || v === null) return v; // string, number, boolean, null, undefined

  const obj = v as object;
  if (seen.has(obj)) return '[Circular]';
  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      return (obj as unknown[]).map((item) => normalize(item, seen));
    }
    return Object.fromEntries(
      Object.keys(obj).sort().map((k) => [k, normalize((obj as Record<string, unknown>)[k], seen)]),
    );
  } finally {
    // Remove on the way back out: this tracks the *current recursion path*, not every
    // node ever visited, so a DAG (same object referenced twice as siblings, not a
    // cycle) still serializes in full both times — only a genuine cycle back to an
    // ancestor gets the '[Circular]' marker.
    seen.delete(obj);
  }
}

export function argsDigest(args: unknown): string {
  return createHash('sha256').update(canonical(args)).digest('hex');
}
