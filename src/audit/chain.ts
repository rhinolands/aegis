import { createHash } from 'node:crypto';
import { canonical, type AuditRecord } from './record.js';

export const GENESIS_HASH = '0'.repeat(64);

// hash_n = sha256(hash_{n-1} || canonical(record_n))
export function computeHash(prevHash: string, rec: AuditRecord): string {
  return createHash('sha256').update(prevHash).update(' ').update(canonical(rec)).digest('hex');
}
