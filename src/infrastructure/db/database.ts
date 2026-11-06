// Kết nối PostgreSQL (pool) + Drizzle + Unit of Work + chạy migration.
import { readFileSync } from 'node:fs';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import pg from 'pg';
import type { Repositories, UnitOfWork } from '../../application/ports.js';
import { createRepositories, type Db } from './repositories.js';
import { schema } from './schema.js';

export interface DbConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  ssl: boolean; // Bật trên AWS (RDS bắt buộc TLS)
  sslCaFile?: string; // File CA của RDS trong image: /etc/ssl/certs/rds-global-bundle.pem
  maxConnections: number;
}

export function createPool(cfg: DbConfig): pg.Pool {
  return new pg.Pool({
    host: cfg.host,
    port: cfg.port,
    database: cfg.database,
    user: cfg.user,
    password: cfg.password,
    max: cfg.maxConnections, // Tổng kết nối = max × số task → phải nhỏ hơn max_connections của RDS
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 3_000, // Không chờ DB quá 3 giây khi lấy kết nối
    statement_timeout: 10_000, // Câu lệnh chạy quá 10 giây bị hủy — tránh kẹt tài nguyên
    application_name: 'ol-iam-service',
    ssl: cfg.ssl
      ? { rejectUnauthorized: true, ...(cfg.sslCaFile ? { ca: readFileSync(cfg.sslCaFile, 'utf8') } : {}) }
      : undefined,
  });
}

export function createDb(pool: pg.Pool): NodePgDatabase<typeof schema> {
  return drizzle(pool, { schema });
}

export class DrizzleUnitOfWork implements UnitOfWork {
  readonly repos: Repositories;
  constructor(private readonly db: NodePgDatabase<typeof schema>) {
    this.repos = createRepositories(db as unknown as Db);
  }
  run<T>(fn: (repos: Repositories) => Promise<T>): Promise<T> {
    // Mọi repository bên trong dùng chung transaction tx; lỗi bất kỳ → rollback toàn bộ
    return this.db.transaction((tx) => fn(createRepositories(tx as unknown as Db)));
  }
}

export async function runMigrations(db: NodePgDatabase<typeof schema>, migrationsFolder: string): Promise<void> {
  // Drizzle ghi lịch sử vào bảng drizzle.__drizzle_migrations; migration đã chạy sẽ được bỏ qua
  await migrate(db, { migrationsFolder });
}
