import { pgTable, uuid, text, timestamp, jsonb, bigint, boolean, integer } from 'drizzle-orm/pg-core';

// Registered agent identities (app-only; never a user)
export const agents = pgTable('agents', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull().unique(),
  tenant: text('tenant').notNull(),
  // allowlists consumed by OPA input; source of truth lives in policy data too
  allowedTools: jsonb('allowed_tools').$type<string[]>().notNull().default([]),
  allowedPeers: jsonb('allowed_peers').$type<string[]>().notNull().default([]),
  allowedModels: jsonb('allowed_models').$type<string[]>().notNull().default([]),
  active: boolean('active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// API keys (bcrypt hash only; raw key returned once at creation)
export const apiKeys = pgTable('api_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  prefix: text('prefix').notNull(),        // first 8 chars, for lookup narrowing
  hash: text('hash').notNull(),            // bcrypt hash of full key
  active: boolean('active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// Scoped backend credentials the gateway injects on the agent's behalf
export const scopedCredentials = pgTable('scoped_credentials', {
  id: uuid('id').primaryKey().defaultRandom(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  target: text('target').notNull(),        // e.g. 'mcp:filesystem', 'llm:anthropic'
  secretCiphertext: text('secret_ciphertext').notNull(), // encrypted at rest
  // Operator-registered upstream destination for this (agent, target) pair.
  // NEVER caller-supplied — resolving this server-side is what prevents an
  // agent from redirecting its own scoped credential to an attacker-controlled
  // host. Nullable because not every target (e.g. non-HTTP tools) has one.
  upstreamUrl: text('upstream_url'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// Per-agent budget + running meter
export const budgets = pgTable('budgets', {
  agentId: uuid('agent_id').primaryKey().references(() => agents.id),
  tokenLimit: bigint('token_limit', { mode: 'number' }).notNull(),
  tokensUsed: bigint('tokens_used', { mode: 'number' }).notNull().default(0),
  costLimitMicros: bigint('cost_limit_micros', { mode: 'number' }).notNull(),
  costUsedMicros: bigint('cost_used_micros', { mode: 'number' }).notNull().default(0),
});

// Append-only audit spine (grants + trigger added by custom migration in Task 7)
export const auditRecords = pgTable('audit_records', {
  seq: bigint('seq', { mode: 'number' }).primaryKey().generatedAlwaysAsIdentity(),
  id: uuid('id').notNull().defaultRandom(),
  ts: timestamp('ts', { withTimezone: true }).notNull().defaultNow(),
  tenant: text('tenant').notNull(),
  subjectKeyId: text('subject_key_id'),    // crypto-shred key id (null if no payload)
  plane: text('plane').notNull(),          // 'mcp' | 'a2a' | 'llm' | 'approval'
  who: jsonb('who').notNull(),             // injected identity + on-behalf-of chain
  what: jsonb('what').notNull(),           // target, operation, args digest
  whenWhere: jsonb('when_where').notNull(),// origin, correlation id
  why: jsonb('why').notNull(),             // reasoning ref; approval events first-class
  verdict: text('verdict').notNull(),      // 'allow' | 'deny'
  policyVersion: text('policy_version').notNull(),
  payloadCiphertext: text('payload_ciphertext'), // encrypted; shred by destroying key
  prevHash: text('prev_hash').notNull(),
  hash: text('hash').notNull(),
});

// Chain head pointer (single row, id='head')
export const chainHead = pgTable('chain_head', {
  id: text('id').primaryKey(),             // always 'head'
  seq: bigint('seq', { mode: 'number' }).notNull(),
  hash: text('hash').notNull(),
});

// Per-subject data keys for crypto-shredding (destroy row = erase subject payloads)
export const subjectKeys = pgTable('subject_keys', {
  keyId: text('key_id').primaryKey(),      // `${tenant}:${subject}`
  wrappedKey: text('wrapped_key').notNull(), // data key encrypted under AUDIT_MASTER_KEY
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
