import { loadConfig } from './config.js';
import { buildServer } from './server.js';
import { log } from './log.js';

const cfg = loadConfig(process.env);
const app = buildServer(cfg);
app.listen({ port: cfg.port, host: '0.0.0.0' })
  .then((addr) => log.info({ addr }, 'aegis listening'))
  .catch((err) => { log.error(err); process.exit(1); });
