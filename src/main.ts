// Điểm khởi động service: đọc config → dựng container → dựng app → mở cổng → tắt êm khi SIGTERM.
import { startServer } from '@ol/node-kit';
import { buildApp } from './app.js';
import { loadAppConfig } from './config.js';
import { buildContainer } from './container.js';

const config = loadAppConfig(); // Sai config → ném lỗi, process dừng với mã khác 0
const container = buildContainer(config);
const c = container.cradle;
const { app } = buildApp(c);

startServer({
  app,
  port: config.PORT,
  logger: c.logger,
  health: c.health,
  drainDelayMs: config.DRAIN_DELAY_MS,
  onShutdown: [() => c.pool.end()], // Đóng mọi kết nối DB khi tắt
});
