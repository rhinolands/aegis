import { readFile } from 'node:fs/promises';
import { loadPolicy as loadOpaPolicy } from '@open-policy-agent/opa-wasm';
import type { PolicyInput } from './input.js';

export interface Decision { allow: boolean; reason: string; policyVersion: string }

export interface PolicyEngine {
  evaluate(input: PolicyInput): Decision;
}

const FAIL_CLOSED: Decision = { allow: false, reason: 'opa error', policyVersion: 'unknown' };

export async function loadPolicy(wasmPath = 'dist/policy.wasm'): Promise<PolicyEngine> {
  const wasm = await readFile(wasmPath);
  const policy = await loadOpaPolicy(wasm);
  return {
    evaluate(input: PolicyInput): Decision {
      try {
        const resultSet = policy.evaluate(input);
        // opa-wasm returns [{ result: <entrypoint output> }]
        const out = resultSet?.[0]?.result as { allow?: unknown; reason?: unknown; policy_version?: unknown } | undefined;
        if (!out || typeof out.allow !== 'boolean') return FAIL_CLOSED;
        return {
          allow: out.allow,
          reason: typeof out.reason === 'string' ? out.reason : '',
          policyVersion: typeof out.policy_version === 'string' ? out.policy_version : 'unknown',
        };
      } catch {
        return FAIL_CLOSED;
      }
    },
  };
}
