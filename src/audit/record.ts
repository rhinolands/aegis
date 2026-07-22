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
// GUARANTEE: normalize() is intrinsically total — it cannot throw for ANY input,
// including hostile ones, by construction of the code below (every fallible
// operation — property enumeration, property read, array length/index read,
// recursion depth — is individually guarded). This is a property of this function
// itself, not of its callers. It feeds argsDigest() and the audit hash chain
// (chain.ts), both of which are called from paths that must never throw (see
// govern.ts). A throw here after an upstream action has already executed turns a
// successful request into an unhandled rejection with no audit trail — the exact
// bug this function closes. That said, callers (govern.ts) should keep their own
// try/catch around audit construction as defense in depth — this guarantee covers
// normalize()'s own logic, not bugs introduced by future edits to it.
//
// Values that plain JSON.stringify cannot represent, or that cannot safely be
// inspected at all, are replaced with a deterministic, clearly-tagged stand-in
// *before* being handed to JSON.stringify, so JSON.stringify itself never sees them
// and never throws:
//   - BigInt                    -> { $type: 'bigint', value: <decimal string> }
//   - function                  -> { $type: 'function', value: <name or '<anonymous>'> }
//   - symbol                    -> { $type: 'symbol', value: <description or ''> }
//   - circular reference        -> the string '[Circular]' at the point of recurrence
//   - key enumeration/access that throws (throwing getter, hostile Proxy `get`/
//     `ownKeys` trap, etc.) -> { $type: 'unserializable' } at the point of failure
//   - recursion past MAX_NORMALIZE_DEPTH (adversarially deep nesting) ->
//     { $type: 'maxdepth' } instead of recursing further
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

// Deliberately chosen: legitimate audit payloads (request args, policy context) are
// shallow data — a handful of levels at most. 100 comfortably exceeds any real input
// while stopping adversarial nesting (e.g. ~100k levels) orders of magnitude before it
// could exhaust the JS call stack (RangeError). Genuine inputs never observe this
// marker; only hostile/pathological ones do.
const MAX_NORMALIZE_DEPTH = 100;

const UNSERIALIZABLE = { $type: 'unserializable' } as const;

function normalize(v: unknown, seen: WeakSet<object>, depth = 0): unknown {
  const t = typeof v;
  if (t === 'bigint') return { $type: 'bigint', value: (v as bigint).toString() };
  if (t === 'function') return { $type: 'function', value: (v as { name?: string }).name || '<anonymous>' };
  if (t === 'symbol') return { $type: 'symbol', value: (v as symbol).description ?? '' };
  if (t !== 'object' || v === null) return v; // string, number, boolean, null, undefined

  const obj = v as object;
  if (seen.has(obj)) return '[Circular]';
  if (depth >= MAX_NORMALIZE_DEPTH) return { $type: 'maxdepth' };
  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      const arr = obj as unknown[];
      let length: number;
      try {
        length = arr.length;
      } catch {
        // A Proxy whose `get` trap throws on `length` (or any other read) — cannot
        // safely inspect this array at all.
        return UNSERIALIZABLE;
      }
      const result: unknown[] = [];
      for (let i = 0; i < length; i++) {
        let item: unknown;
        try {
          item = arr[i];
        } catch {
          // Throwing getter / hostile Proxy `get` trap on this index — substitute a
          // stable marker for this element only; the rest of the array is unaffected.
          result.push(UNSERIALIZABLE);
          continue;
        }
        result.push(normalize(item, seen, depth + 1));
      }
      return result;
    }

    let keys: string[];
    try {
      keys = Object.keys(obj).sort();
    } catch {
      // A Proxy whose `ownKeys` (or `getOwnPropertyDescriptor`) trap throws — cannot
      // safely enumerate this object's keys at all.
      return UNSERIALIZABLE;
    }
    return Object.fromEntries(
      keys.map((k) => {
        let val: unknown;
        try {
          val = (obj as Record<string, unknown>)[k];
        } catch {
          // Throwing getter / hostile Proxy `get` trap on this property — substitute a
          // stable marker for this key only; sibling keys still serialize normally.
          return [k, UNSERIALIZABLE];
        }
        return [k, normalize(val, seen, depth + 1)];
      }),
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
