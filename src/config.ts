// Runtime config của IAM service — đọc từ biến môi trường, kiểm tra bằng Zod khi khởi động.
// Giá trị bí mật (DB_PASSWORD, IAM_CLIENT_SECRET) được ECS tiêm từ AWS Secrets Manager;
// ở local lấy từ ol-infra/local/.env (không commit).
import { envBoolean, loadConfig } from '@ol/node-kit';
import { z } from 'zod';

const DbSchema = z.object({
  APP_ENV: z.enum(['local', 'dev', 'staging', 'prod']).default('local'),
  LOG_LEVEL: z.string().default('info'),
  DB_HOST: z.string().min(1),
  DB_PORT: z.coerce.number().int().positive().default(5432),
  DB_NAME: z.string().default('iam'),
  DB_USER: z.string().min(1),
  DB_PASSWORD: z.string().min(1),
  DB_SSL: z.string().optional(),
  DB_SSL_CA_FILE: z.string().optional(),
  DB_POOL_MAX: z.coerce.number().int().positive().default(10),
});

const AppSchema = DbSchema.extend({
  PORT: z.coerce.number().int().positive().default(3000),
  OIDC_ISSUER: z.url(), // https://id.ol.test/realms/ol — phải khớp claim iss
  OIDC_AUDIENCE: z.string().default('ol-api'),
  OIDC_INTERNAL_ISSUER: z.url().optional(), // http://keycloak:8080/realms/ol — chấp nhận thêm nếu token mang iss nội bộ
  KEYCLOAK_INTERNAL_URL: z.url(), // http://keycloak:8080 — gọi nội bộ, không qua Internet
  KEYCLOAK_REALM: z.string().default('ol'),
  IAM_CLIENT_ID: z.string().default('ol-iam-service'),
  IAM_CLIENT_SECRET: z.string().min(16),
  APP_URL: z.url(), // https://app.ol.test — link trong email quay về đây
  INVITE_CLIENT_ID: z.string().default('ol-bff'),
  DRAIN_DELAY_MS: z.coerce.number().int().nonnegative().default(5_000),
  SEED_PASSWORD: z.string().optional(), // Chỉ dùng cho lệnh seed-demo ở local
});

export type DbEnv = z.infer<typeof DbSchema>;
export type AppConfig = z.infer<typeof AppSchema>;

export function loadDbConfig(): DbEnv {
  return loadConfig(DbSchema);
}

export function loadAppConfig(): AppConfig {
  return loadConfig(AppSchema);
}

export function dbOptions(cfg: DbEnv) {
  return {
    host: cfg.DB_HOST,
    port: cfg.DB_PORT,
    database: cfg.DB_NAME,
    user: cfg.DB_USER,
    password: cfg.DB_PASSWORD,
    ssl: envBoolean(cfg.DB_SSL),
    sslCaFile: cfg.DB_SSL_CA_FILE,
    maxConnections: cfg.DB_POOL_MAX,
  };
}
