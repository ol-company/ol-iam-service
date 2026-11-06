// Dựng ứng dụng Express từ container — tách khỏi main.ts để test dùng lại (Supertest) mà không mở cổng.
import express, { type Express } from 'express';
import helmet from 'helmet';
import { accessLogMiddleware, errorHandler, healthRouter, notFoundHandler, requestContextMiddleware } from '@ol/node-kit';
import type { Cradle } from './container.js';
import { buildRoutes } from './interfaces/http/routes.js';

export function buildApp(c: Cradle): { app: Express; routes: ReturnType<typeof buildRoutes> } {
  const app = express();
  app.disable('x-powered-by'); // Không lộ framework đang dùng
  app.set('trust proxy', 'uniquelocal'); // Tin X-Forwarded-For từ mạng nội bộ (BFF) để audit đúng IP người dùng
  app.use(helmet()); // Header bảo mật mặc định
  app.use(requestContextMiddleware());
  app.use(accessLogMiddleware(c.logger));
  app.use(express.json({ limit: '100kb' })); // Giới hạn kích thước body chống DoS
  app.use(healthRouter(c.health, { db: () => c.pool.query('SELECT 1') }));
  const routes = buildRoutes(c);
  app.use(routes.router);
  app.use(notFoundHandler());
  app.use(errorHandler(c.logger));
  return { app, routes };
}
