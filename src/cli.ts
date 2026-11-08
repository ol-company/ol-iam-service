// Lệnh quản trị chạy một lần (ECS run-task hoặc docker compose run):
//   bootstrap-platform-admin --email <email>   Tạo platform admin đầu tiên (từ chối nếu đã có)
//   seed-demo                                  Tạo dữ liệu mẫu (chỉ local/dev, cần SEED_PASSWORD)
import { parseArgs } from 'node:util';
import { loadAppConfig } from './config.js';
import { buildContainer } from './container.js';

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: { email: { type: 'string' } },
});
const command = positionals[0];
const config = loadAppConfig();
const container = buildContainer(config);
const { bootstrapService, logger, pool } = container.cradle;

try {
  switch (command) {
    case 'bootstrap-platform-admin': {
      if (!values.email) throw new Error('Thiếu --email');
      const result = await bootstrapService.bootstrapPlatformAdmin(values.email);
      // Không in mật khẩu hay link — người dùng nhận email đặt mật khẩu + MFA
      logger.info(
        { userId: result.userId, email: result.email },
        'Đã tạo platform admin, email kích hoạt đã được gửi',
      );
      break;
    }
    case 'seed-demo': {
      if (!config.SEED_PASSWORD) throw new Error('Thiếu biến SEED_PASSWORD');
      const lines = await bootstrapService.seedDemo(config.APP_ENV, config.SEED_PASSWORD);
      for (const line of lines) logger.info(line);
      break;
    }
    default:
      throw new Error(
        `Lệnh không hợp lệ: ${command ?? '(trống)'}. Dùng: bootstrap-platform-admin | seed-demo`,
      );
  }
} catch (err) {
  logger.error({ err }, 'cli_failed');
  process.exitCode = 1;
} finally {
  await pool.end();
}
