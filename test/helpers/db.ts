// Dựng PostgreSQL thật trong Docker (Testcontainers) giống môi trường deploy:
// tạo role iam_migrator/iam_app giống ol-infra/db/bootstrap.sql, chạy migration bằng iam_migrator,
// rồi trả pool kết nối bằng iam_app (role ứng dụng, chỉ có quyền DML).
import { fileURLToPath } from 'node:url';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import pg from 'pg';
import { syncCatalog } from '../../src/application/bootstrap-service.js';
import { createDb, DrizzleUnitOfWork, runMigrations } from '../../src/infrastructure/db/database.js';

export interface TestDb {
  container: StartedPostgreSqlContainer;
  appPool: pg.Pool;
  stop(): Promise<void>;
}

export async function startTestDb(): Promise<TestDb> {
  const container = await new PostgreSqlContainer('postgres:17-alpine').withDatabase('iam').start();
  const admin = new pg.Client({ connectionString: container.getConnectionUri() });
  await admin.connect();
  // Giống bootstrap.sql: migrator sở hữu schema; app chỉ nhận quyền DML qua default privileges
  await admin.query(`
    CREATE ROLE iam_migrator LOGIN PASSWORD 'migrator';
    CREATE ROLE iam_app LOGIN PASSWORD 'app';
    GRANT CREATE, CONNECT ON DATABASE iam TO iam_migrator;
    GRANT CONNECT ON DATABASE iam TO iam_app;
    CREATE SCHEMA iam AUTHORIZATION iam_migrator;
    GRANT USAGE ON SCHEMA iam TO iam_app;
    ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrator IN SCHEMA iam GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO iam_app;
    ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrator IN SCHEMA iam GRANT USAGE, SELECT ON SEQUENCES TO iam_app;
    ALTER DEFAULT PRIVILEGES FOR ROLE iam_migrator IN SCHEMA iam GRANT EXECUTE ON FUNCTIONS TO iam_app;
  `);
  await admin.end();

  const base = { host: container.getHost(), port: container.getPort(), database: 'iam' };
  const migratorPool = new pg.Pool({ ...base, user: 'iam_migrator', password: 'migrator', max: 1 });
  const migratorDb = createDb(migratorPool);
  await runMigrations(migratorDb, fileURLToPath(new URL('../../migrations', import.meta.url)));
  await syncCatalog(new DrizzleUnitOfWork(migratorDb));
  await migratorPool.end();

  const appPool = new pg.Pool({ ...base, user: 'iam_app', password: 'app', max: 5 });
  return {
    container,
    appPool,
    async stop() {
      await appPool.end();
      await container.stop();
    },
  };
}
