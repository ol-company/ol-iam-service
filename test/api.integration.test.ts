// Test tích hợp: PostgreSQL thật + Express thật + Keycloak giả.
// Kiểm chứng đúng tiêu chí của Bước 3: truy cập hợp lệ, thiếu quyền, chéo tenant, audit, hợp đồng authorize.
import { asValue } from 'awilix';
import { AuthorizeResponseSchema } from '@ol/node-kit';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app.js';
import type { AppConfig } from '../src/config.js';
import { buildContainer } from '../src/container.js';
import { FakeIdp, FakeVerifier } from './helpers/fakes.js';
import { startTestDb, type TestDb } from './helpers/db.js';

let db: TestDb;
let app: ReturnType<typeof buildApp>['app'];
let routes: ReturnType<typeof buildApp>['routes'];
const idp = new FakeIdp();
const ids = { acme: '', globex: '', acmeAdmin: '', acmeOperator: '', globexViewer: '' };

const config = {
  APP_ENV: 'local',
  LOG_LEVEL: 'silent',
  PORT: 0,
  DB_HOST: 'unused',
  DB_PORT: 5432,
  DB_NAME: 'iam',
  DB_USER: 'unused',
  DB_PASSWORD: 'unused',
  DB_POOL_MAX: 5,
  OIDC_ISSUER: 'https://id.ol.test/realms/ol',
  OIDC_AUDIENCE: 'ol-api',
  KEYCLOAK_INTERNAL_URL: 'http://keycloak:8080',
  KEYCLOAK_REALM: 'ol',
  IAM_CLIENT_ID: 'ol-iam-service',
  IAM_CLIENT_SECRET: 'x'.repeat(32),
  APP_URL: 'https://app.ol.test',
  INVITE_CLIENT_ID: 'ol-bff',
  DRAIN_DELAY_MS: 0,
} as AppConfig;

const as = (userId: string, email = 'x@test') => `Bearer user:${userId}:${email}`;

beforeAll(async () => {
  db = await startTestDb();
  const container = buildContainer(config, {
    pool: db.appPool,
    overrides: { idp: asValue(idp), tokenVerifier: asValue(new FakeVerifier()) },
  });
  ({ app, routes } = buildApp(container.cradle));

  // Dữ liệu: 2 tenant, admin ACME đã bật MFA, operator ACME, viewer Globex
  const seedUser = (email: string, otp: boolean) => idp.addUser(email, otp);
  ids.acmeAdmin = seedUser('admin@acme.test', true);
  ids.acmeOperator = seedUser('op@acme.test', false);
  ids.globexViewer = seedUser('viewer@globex.test', false);
  const { bootstrapService } = container.cradle;
  // Dùng use case thật để tạo dữ liệu, sau đó kích hoạt người dùng bằng /v1/me (giống lần đăng nhập đầu)
  const uow = container.cradle.uow;
  await uow.run(async (r) => {
    const acme = await r.tenants.create({ slug: 'acme', name: 'ACME' });
    const globex = await r.tenants.create({ slug: 'globex', name: 'Globex' });
    ids.acme = acme.id;
    ids.globex = globex.id;
    for (const [uid, email, tid, role] of [
      [ids.acmeAdmin, 'admin@acme.test', acme.id, 'roles/iam.tenantAdmin'],
      [ids.acmeOperator, 'op@acme.test', acme.id, 'roles/warehouse.operator'],
      [ids.globexViewer, 'viewer@globex.test', globex.id, 'roles/warehouse.viewer'],
    ] as const) {
      await r.users.insert({ id: uid, email, displayName: null, status: 'invited' });
      await r.memberships.add(tid, uid);
      await r.bindings.create({ tenantId: tid, principalType: 'user', principalId: uid, roleId: role, resource: `tenants/${tid}`, createdBy: 'test', expiresAt: null });
    }
  });
  void bootstrapService;
  for (const [uid, email] of [[ids.acmeAdmin, 'admin@acme.test'], [ids.acmeOperator, 'op@acme.test'], [ids.globexViewer, 'viewer@globex.test']]) {
    await request(app).get('/v1/me').set('authorization', as(uid!, email)).expect(200);
  }
});

afterAll(async () => {
  await db?.stop();
});

describe('IAM API', () => {
  it('/v1/me chỉ trả tenant mà người dùng là thành viên', async () => {
    const res = await request(app).get('/v1/me').set('authorization', as(ids.acmeOperator, 'op@acme.test')).expect(200);
    expect(res.body.tenants.map((t: { slug: string }) => t.slug)).toEqual(['acme']);
    expect(res.body.user.status).toBe('active');
  });

  it('không có token → 401', async () => {
    await request(app).get(`/v1/tenants/${ids.acme}/users`).expect(401);
  });

  it('truy cập hợp lệ: admin ACME xem người dùng ACME', async () => {
    const res = await request(app).get(`/v1/tenants/${ids.acme}/users`).set('authorization', as(ids.acmeAdmin)).expect(200);
    expect(res.body).toHaveLength(2);
  });

  it('thiếu quyền: operator không xem được danh sách người dùng', async () => {
    const res = await request(app).get(`/v1/tenants/${ids.acme}/users`).set('authorization', as(ids.acmeOperator)).expect(403);
    expect(res.body.details.reason).toBe('no-binding');
  });

  it('chéo tenant: admin ACME không vào được Globex', async () => {
    const res = await request(app).get(`/v1/tenants/${ids.globex}/users`).set('authorization', as(ids.acmeAdmin)).expect(403);
    expect(res.body.details.reason).toBe('not-member');
  });

  it('mời người dùng → 201, có binding và bản ghi audit', async () => {
    const res = await request(app)
      .post(`/v1/tenants/${ids.acme}/invitations`)
      .set('authorization', as(ids.acmeAdmin))
      .send({ email: 'new@acme.test', roleIds: ['roles/warehouse.viewer'] })
      .expect(201);
    expect(res.body.status).toBe('pending');
    expect(idp.emails.at(-1)?.actions).toContain('UPDATE_PASSWORD');
    const audit = await request(app).get(`/v1/tenants/${ids.acme}/audit-events`).set('authorization', as(ids.acmeAdmin)).expect(200);
    expect(audit.body[0].action).toBe('iam.user.invited');
  });

  it('không gán được role platform trong tenant', async () => {
    await request(app)
      .post(`/v1/tenants/${ids.acme}/invitations`)
      .set('authorization', as(ids.acmeAdmin))
      .send({ email: 'evil@acme.test', roleIds: ['roles/platform.admin'] })
      .expect(400);
  });

  it('không gỡ được quản trị viên cuối cùng', async () => {
    const list = await request(app).get(`/v1/tenants/${ids.acme}/role-bindings`).set('authorization', as(ids.acmeAdmin)).expect(200);
    const adminBinding = list.body.find((b: { roleId: string }) => b.roleId === 'roles/iam.tenantAdmin');
    await request(app).delete(`/v1/tenants/${ids.acme}/role-bindings/${adminBinding.id}`).set('authorization', as(ids.acmeAdmin)).expect(409);
  });

  it('vô hiệu hóa thành viên có hiệu lực ngay ở authorize', async () => {
    const check = () =>
      request(app)
        .post('/internal/v1/authorize')
        .set('authorization', 'Bearer service:ol-warehouse-service')
        .send({ principal: `users/${ids.acmeOperator}`, permission: 'warehouse.items.list', resource: `tenants/${ids.acme}/warehouses/w1` });
    expect((await check().expect(200)).body.allow).toBe(true);
    await request(app).post(`/v1/tenants/${ids.acme}/users/${ids.acmeOperator}/disable`).set('authorization', as(ids.acmeAdmin)).expect(204);
    const after = await check().expect(200);
    expect(after.body).toMatchObject({ allow: false, reason: 'membership-disabled' });
  });

  it('HỢP ĐỒNG: phản hồi authorize khớp schema của @ol/node-kit', async () => {
    const res = await request(app)
      .post('/internal/v1/authorize')
      .set('authorization', 'Bearer service:ol-warehouse-service')
      .send({ principal: `users/${ids.globexViewer}`, permission: 'warehouse.items.list', resource: `tenants/${ids.acme}` })
      .expect(200);
    expect(AuthorizeResponseSchema.safeParse(res.body).success).toBe(true);
    expect(res.body.allow).toBe(false);
  });

  it('service không có role authzChecker không gọi được authorize', async () => {
    await request(app)
      .post('/internal/v1/authorize')
      .set('authorization', 'Bearer service:ol-bff')
      .send({ principal: `users/${ids.acmeAdmin}`, permission: 'iam.users.list', resource: `tenants/${ids.acme}` })
      .expect(403);
  });

  it('mọi route đều khai báo policy; route /internal không public', () => {
    for (const d of routes.definitions) {
      expect(d.policy).toBeDefined();
      if (d.path.startsWith('/internal')) expect(d.policy.kind).toBe('permission');
    }
  });
});
