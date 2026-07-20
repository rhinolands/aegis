import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: z.coerce.number().int().positive().default(8080),
  DATABASE_URL: z.string().url().or(z.string().startsWith('postgres')),
  JWT_JWKS_URLS: z.string().default(''),
  AUDIT_MASTER_KEY: z.string(),
  EXPORT_S3_ENDPOINT: z.string().default(''),
  EXPORT_S3_BUCKET: z.string().default('aegis-audit'),
  EXPORT_S3_ACCESS_KEY: z.string().default(''),
  EXPORT_S3_SECRET_KEY: z.string().default(''),
  EXPORT_S3_REGION: z.string().default('us-east-1'),
});

export interface Config {
  nodeEnv: string;
  port: number;
  databaseUrl: string;
  jwksUrls: string[];
  auditMasterKey: Buffer;
  s3: { endpoint: string; bucket: string; accessKey: string; secretKey: string; region: string };
}

export function loadConfig(env: NodeJS.ProcessEnv): Config {
  const p = schema.parse(env);
  const key = Buffer.from(p.AUDIT_MASTER_KEY, 'base64');
  if (key.length !== 32) throw new Error('AUDIT_MASTER_KEY must decode to 32 bytes');
  return {
    nodeEnv: p.NODE_ENV,
    port: p.PORT,
    databaseUrl: p.DATABASE_URL,
    jwksUrls: p.JWT_JWKS_URLS.split(',').map((s) => s.trim()).filter(Boolean),
    auditMasterKey: key,
    s3: {
      endpoint: p.EXPORT_S3_ENDPOINT, bucket: p.EXPORT_S3_BUCKET,
      accessKey: p.EXPORT_S3_ACCESS_KEY, secretKey: p.EXPORT_S3_SECRET_KEY, region: p.EXPORT_S3_REGION,
    },
  };
}
