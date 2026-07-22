import { loadConfig } from './config.js';
import { getDb } from './db/client.js';
import { loadPolicy } from './policy/opa.js';
import { buildServer } from './server.js';
import { log } from './log.js';

async function main(): Promise<void> {
  const cfg = loadConfig(process.env);
  const { db, sql } = getDb(cfg);
  const engine = await loadPolicy(process.env.POLICY_WASM ?? 'dist/policy.wasm');
  const app = buildServer({ cfg, db, engine });

  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info({ signal }, 'aegis shutting down');
    app.close()
      .finally(() => sql.end({ timeout: 5 }))
      .then(() => process.exit(0))
      .catch((err) => { log.error(err, 'error during shutdown'); process.exit(1); });
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  const addr = await app.listen({ port: cfg.port, host: '0.0.0.0' });
  log.info({ addr }, 'aegis listening');
}

main().catch((err) => {
  log.error(err, 'aegis failed to start');
  process.exit(1);
});
