import { describe, it, expect } from 'vitest';
import { loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  const base = {
    DATABASE_URL: 'postgres://u:p@localhost:5432/db',
    AUDIT_MASTER_KEY: Buffer.alloc(32, 7).toString('base64'),
  };
  it('parses valid env with defaults', () => {
    const cfg = loadConfig(base as NodeJS.ProcessEnv);
    expect(cfg.port).toBe(8080);
    expect(cfg.databaseUrl).toContain('postgres://');
    expect(cfg.auditMasterKey).toHaveLength(32);
  });
  it('throws when DATABASE_URL missing', () => {
    expect(() => loadConfig({ AUDIT_MASTER_KEY: base.AUDIT_MASTER_KEY } as NodeJS.ProcessEnv)).toThrow();
  });
  it('throws when AUDIT_MASTER_KEY is not 32 bytes', () => {
    expect(() => loadConfig({ ...base, AUDIT_MASTER_KEY: 'short' } as NodeJS.ProcessEnv)).toThrow();
  });
});
