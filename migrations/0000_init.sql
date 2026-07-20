CREATE TABLE "agents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"tenant" text NOT NULL,
	"allowed_tools" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_peers" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_models" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "agents_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "api_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"agent_id" uuid NOT NULL,
	"prefix" text NOT NULL,
	"hash" text NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_records" (
	"seq" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "audit_records_seq_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"id" uuid DEFAULT gen_random_uuid() NOT NULL,
	"ts" timestamp with time zone DEFAULT now() NOT NULL,
	"tenant" text NOT NULL,
	"subject_key_id" text,
	"plane" text NOT NULL,
	"who" jsonb NOT NULL,
	"what" jsonb NOT NULL,
	"when_where" jsonb NOT NULL,
	"why" jsonb NOT NULL,
	"verdict" text NOT NULL,
	"policy_version" text NOT NULL,
	"payload_ciphertext" text,
	"prev_hash" text NOT NULL,
	"hash" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "budgets" (
	"agent_id" uuid PRIMARY KEY NOT NULL,
	"token_limit" bigint NOT NULL,
	"tokens_used" bigint DEFAULT 0 NOT NULL,
	"cost_limit_micros" bigint NOT NULL,
	"cost_used_micros" bigint DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "chain_head" (
	"id" text PRIMARY KEY NOT NULL,
	"seq" bigint NOT NULL,
	"hash" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scoped_credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"agent_id" uuid NOT NULL,
	"target" text NOT NULL,
	"secret_ciphertext" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "subject_keys" (
	"key_id" text PRIMARY KEY NOT NULL,
	"wrapped_key" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "budgets" ADD CONSTRAINT "budgets_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scoped_credentials" ADD CONSTRAINT "scoped_credentials_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE no action ON UPDATE no action;