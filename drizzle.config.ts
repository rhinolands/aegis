import { defineConfig } from 'drizzle-kit';

// Run migrations with NOTICE-level chatter suppressed.
//
// The append-only migration issues `DROP TRIGGER IF EXISTS` before creating its
// trigger, so a fresh database emits a `does not exist, skipping` notice that reads
// like a failure to anyone running the quickstart. Only NOTICE/INFO/DEBUG are
// filtered — warnings and errors still surface.
//
// This is set on the connection rather than inside the migration on purpose:
// migrations here are append-only and are never edited once applied.
const QUIET_NOTICES = 'options=-c%20client_min_messages%3Dwarning';

export function migrationUrl(raw: string): string {
  if (!raw) return '';
  if (raw.includes('client_min_messages')) return raw;
  return `${raw}${raw.includes('?') ? '&' : '?'}${QUIET_NOTICES}`;
}

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './migrations',
  dialect: 'postgresql',
  dbCredentials: { url: migrationUrl(process.env.DATABASE_URL ?? '') },
});
