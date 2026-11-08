// Chạy migration + đồng bộ danh mục permission/role. Chạy như task riêng TRƯỚC khi deploy phiên bản mới,
// với tài khoản DB "iam_migrator" (có quyền DDL). Service bình thường dùng "iam_app" (chỉ DML).
import { fileURLToPath } from 'node:url';
import { createLogger } from '@ol/node-kit';
import { syncCatalog } from './application/bootstrap-service.js';
import { dbOptions, loadDbConfig } from './config.js';
import {
  createDb,
  createPool,
  DrizzleUnitOfWork,
  runMigrations,
} from './infrastructure/db/database.js';

const cfg = loadDbConfig();
const logger = createLogger({ service: 'ol-iam-service-migrate', level: cfg.LOG_LEVEL });
const pool = createPool({ ...dbOptions(cfg), maxConnections: 1 });
const db = createDb(pool);
// Thư mục migrations nằm cạnh dist/ trong image: /app/migrations
const migrationsFolder = fileURLToPath(new URL('../migrations', import.meta.url));

try {
  logger.info({ migrationsFolder }, 'migrate_start');
  await runMigrations(db, migrationsFolder); // 1. Thay đổi cấu trúc bảng
  await syncCatalog(new DrizzleUnitOfWork(db)); // 2. Đồng bộ permission/role hệ thống từ code
  logger.info('migrate_done');
} catch (err) {
  logger.error({ err }, 'migrate_failed');
  process.exitCode = 1; // Task kết thúc với mã 1 → pipeline dừng, không deploy phiên bản mới
} finally {
  await pool.end();
}
