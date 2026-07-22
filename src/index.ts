import { loadConfig } from './config.js';
import { buildServer } from './server.js';
import { getDb } from './db/client.js';
import { loadPolicy } from './policy/opa.js';
import { log } from './log.js';

const cfg = loadConfig(process.env);
const { db } = getDb(cfg);
const engine = await loadPolicy();
const app = buildServer({ cfg, db, engine });
app.listen({ port: cfg.port, host: '0.0.0.0' })
  .then((addr) => log.info({ addr }, 'aegis listening'))
  .catch((err) => { log.error(err); process.exit(1); });
