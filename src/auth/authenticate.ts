import type { FastifyRequest } from 'fastify';
import type { DrizzleDb } from '../db/client.js';
import type { Config } from '../config.js';
import type { Principal } from '../identity/principal.js';
import { verifyApiKey } from './apikey.js';
import { verifyJwt } from './jwt.js';

export class AuthError extends Error {}

export async function authenticateApiKey(db: DrizzleDb, raw: string): Promise<Principal> {
  const p = await verifyApiKey(db, raw);
  if (!p) throw new AuthError('invalid api key');
  return p;
}

// Edge AuthN entrypoint: Bearer JWT or `X-Api-Key`. Fail closed.
export async function authenticate(db: DrizzleDb, cfg: Config, req: FastifyRequest): Promise<Principal> {
  const apiKey = req.headers['x-api-key'];
  if (typeof apiKey === 'string' && apiKey) return authenticateApiKey(db, apiKey);

  const authz = req.headers['authorization'];
  if (typeof authz === 'string' && authz.startsWith('Bearer ')) {
    const p = await verifyJwt(db, cfg, authz.slice(7));
    if (p) return p;
  }
  throw new AuthError('no valid credential');
}
