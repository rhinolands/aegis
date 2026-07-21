import { describe, it, expect, beforeAll } from 'vitest';
import { loadPolicy, type PolicyEngine } from '../src/policy/opa.js';
import { buildInput } from '../src/policy/input.js';

const agent = { id: 'a', name: 'a', tenant: 't', allowedTools: ['fs.read'], allowedPeers: ['b'], allowedModels: ['claude-sonnet-5'], active: true, createdAt: new Date() };
let engine: PolicyEngine;
beforeAll(async () => { engine = await loadPolicy('dist/policy.wasm'); });

describe('PolicyEngine', () => {
  it('allows a whitelisted tool', () => {
    const d = engine.evaluate(buildInput('mcp', agent as any, { tool: 'fs.read', operation: 'call' }));
    expect(d.allow).toBe(true);
  });
  it('denies an unknown tool', () => {
    const d = engine.evaluate(buildInput('mcp', agent as any, { tool: 'fs.write', operation: 'call' }));
    expect(d.allow).toBe(false);
  });
  it('denies an unknown model', () => {
    const d = engine.evaluate(buildInput('llm', agent as any, { model: 'gpt-4', operation: 'complete' }));
    expect(d.allow).toBe(false);
  });

  it('fails closed when the wasm path is bogus (load rejects, never allows)', async () => {
    await expect(loadPolicy('dist/does-not-exist.wasm')).rejects.toBeTruthy();
  });

  it('fails closed when evaluate is given input that makes the wasm module throw', () => {
    // A circular-reference input cannot be JSON.stringify'd by opa-wasm's evaluate,
    // so the underlying call throws synchronously. The wrapper must swallow this
    // and return the fail-closed decision rather than propagating.
    const circular: any = { plane: 'mcp', agent: {}, request: {} };
    circular.self = circular;
    const d = engine.evaluate(circular);
    expect(d).toEqual({ allow: false, reason: 'opa error', policyVersion: 'unknown' });
  });
});
