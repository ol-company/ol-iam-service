// Khởi tạo hệ thống:
//  - syncCatalog: đồng bộ permission/role hệ thống và binding cho service (chạy mỗi lần migrate)
//  - bootstrapPlatformAdmin: tạo quản trị viên platform ĐẦU TIÊN, từ chối nếu đã có
//  - seedDemo: dữ liệu mẫu cho môi trường local (bị chặn ở môi trường khác)
import { ConflictError } from '@ol/node-kit';
import { AUTHZ_CHECKER_SERVICES, PERMISSIONS, SYSTEM_ROLES } from '../domain/catalog.js';
import { PLATFORM, tenantResource } from '../domain/resource.js';
import type { Actor } from '../domain/types.js';
import { audit } from './audit.js';
import type { IdentityProvider, UnitOfWork } from './ports.js';

const SYSTEM_ACTOR: Actor = { id: 'system:bootstrap' };

// Đồng bộ danh mục từ code vào DB — không cần Identity Provider nên tách thành hàm độc lập
export async function syncCatalog(uow: UnitOfWork): Promise<void> {
  await uow.run(async (r) => {
    await r.roles.syncCatalog(PERMISSIONS, SYSTEM_ROLES);
    for (const clientId of AUTHZ_CHECKER_SERVICES) {
      await r.bindings.ensure({
        tenantId: null,
        principalType: 'service',
        principalId: clientId,
        roleId: 'roles/iam.authzChecker',
        resource: PLATFORM,
        createdBy: SYSTEM_ACTOR.id,
      });
    }
  });
}

export class BootstrapService {
  private readonly uow: UnitOfWork;
  private readonly idp: IdentityProvider;

  constructor(deps: { uow: UnitOfWork; idp: IdentityProvider }) {
    this.uow = deps.uow;
    this.idp = deps.idp;
  }

  syncCatalog(): Promise<void> {
    return syncCatalog(this.uow);
  }

  async bootstrapPlatformAdmin(email: string): Promise<{ userId: string; email: string }> {
    const normalized = email.trim().toLowerCase();
    if ((await this.uow.repos.bindings.countForRole('roles/platform.admin', PLATFORM)) > 0) {
      throw new ConflictError(
        'Đã có platform admin. Bootstrap chỉ chạy một lần; dùng tài khoản admin hiện có để cấp thêm.',
      );
    }
    const existing = await this.idp.findUserByEmail(normalized);
    const userId =
      existing?.id ??
      (await this.idp.createUser({
        email: normalized,
        requiredActions: ['UPDATE_PASSWORD', 'VERIFY_EMAIL', 'CONFIGURE_TOTP'],
      }));
    if (existing) await this.idp.addRequiredActions(userId, ['CONFIGURE_TOTP']);

    await this.uow.run(async (r) => {
      if (!(await r.users.findById(userId))) {
        await r.users.insert({
          id: userId,
          email: normalized,
          displayName: null,
          status: 'invited',
        });
      }
      await r.bindings.create({
        tenantId: null,
        principalType: 'user',
        principalId: userId,
        roleId: 'roles/platform.admin',
        resource: PLATFORM,
        createdBy: SYSTEM_ACTOR.id,
        expiresAt: null,
      });
      await audit(r, SYSTEM_ACTOR, {
        tenantId: null,
        action: 'platform.admin.bootstrapped',
        resource: `${PLATFORM}/users/${userId}`,
        details: { email: normalized },
      });
    });

    if (!existing)
      await this.idp.sendActionsEmail(
        userId,
        ['UPDATE_PASSWORD', 'VERIFY_EMAIL', 'CONFIGURE_TOTP'],
        72 * 3600,
      );
    return { userId, email: normalized };
  }

  // CHỈ cho local/dev: tạo 2 tenant và 3 người dùng có mật khẩu đặt sẵn
  async seedDemo(appEnv: string, password: string): Promise<string[]> {
    if (!['local', 'dev'].includes(appEnv))
      throw new Error('seedDemo bị chặn ngoài môi trường local/dev');
    if (password.length < 12) throw new Error('SEED_PASSWORD phải dài ít nhất 12 ký tự');
    const log: string[] = [];
    const tenantsDef = [
      { slug: 'acme', name: 'ACME Logistics' },
      { slug: 'globex', name: 'Globex Warehousing' },
    ];
    const usersDef = [
      {
        email: 'admin@acme.test',
        tenant: 'acme',
        roles: ['roles/iam.tenantAdmin', 'roles/warehouse.manager'],
        mfa: true,
      },
      {
        email: 'operator@acme.test',
        tenant: 'acme',
        roles: ['roles/warehouse.operator'],
        mfa: false,
      },
      {
        email: 'viewer@globex.test',
        tenant: 'globex',
        roles: ['roles/warehouse.viewer'],
        mfa: false,
      },
    ];

    const tenantIds = new Map<string, string>();
    for (const t of tenantsDef) {
      const found = await this.uow.repos.tenants.findBySlug(t.slug);
      const tenant = found ?? (await this.uow.run((r) => r.tenants.create(t)));
      tenantIds.set(t.slug, tenant.id);
      log.push(`tenant ${t.slug} = ${tenant.id}`);
    }

    for (const u of usersDef) {
      const tenantId = tenantIds.get(u.tenant)!;
      let idpUser = await this.idp.findUserByEmail(u.email);
      if (!idpUser) {
        const id = await this.idp.createUser({
          email: u.email,
          requiredActions: u.mfa ? ['CONFIGURE_TOTP'] : [],
          emailVerified: true,
        });
        await this.idp.setPassword(id, password, false);
        idpUser = { id, email: u.email, enabled: true, displayName: null };
      }
      const userId = idpUser.id;
      await this.uow.run(async (r) => {
        if (!(await r.users.findById(userId)))
          await r.users.insert({ id: userId, email: u.email, displayName: null, status: 'active' });
        await r.memberships.add(tenantId, userId);
        for (const roleId of u.roles) {
          await r.bindings.ensure({
            tenantId,
            principalType: 'user',
            principalId: userId,
            roleId,
            resource: tenantResource(tenantId),
            createdBy: SYSTEM_ACTOR.id,
          });
        }
      });
      log.push(`user ${u.email} → ${u.tenant} [${u.roles.join(', ')}]`);
    }
    return log;
  }
}
