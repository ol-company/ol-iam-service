// Use case tenant: platform admin tạo tenant kèm lời mời quản trị viên đầu tiên của tenant.
import { NotFoundError } from '@ol/node-kit';
import { tenantResource } from '../domain/resource.js';
import type { Actor } from '../domain/types.js';
import { audit } from './audit.js';
import type { UnitOfWork } from './ports.js';
import type { UserService } from './user-service.js';

export class TenantService {
  private readonly uow: UnitOfWork;
  private readonly userService: UserService;

  constructor(deps: { uow: UnitOfWork; userService: UserService }) {
    this.uow = deps.uow;
    this.userService = deps.userService;
  }

  list() {
    return this.uow.repos.tenants.list();
  }

  async get(tenantId: string) {
    const t = await this.uow.repos.tenants.findById(tenantId);
    if (!t) throw new NotFoundError('Không tìm thấy tenant');
    return t;
  }

  async create(actor: Actor, input: { slug: string; name: string; adminEmail: string }) {
    // Chuẩn bị tài khoản quản trị viên ở Keycloak trước (ngoài transaction, idempotent theo email)
    const prep = await this.userService.prepareInvite(
      input.adminEmail,
      ['roles/iam.tenantAdmin'],
      true,
    );
    const tenant = await this.uow.run(async (r) => {
      const t = await r.tenants.create({ slug: input.slug, name: input.name });
      await audit(r, actor, {
        tenantId: t.id,
        action: 'platform.tenant.created',
        resource: tenantResource(t.id),
        details: { slug: t.slug },
      });
      await this.userService.persistInvite(r, actor, t.id, prep);
      return t;
    });
    await this.userService.afterInvite(prep);
    return tenant;
  }

  listPlatformAudit(beforeId: number | undefined, limit: number) {
    return this.uow.repos.audit.list({ tenantId: null, beforeId, limit });
  }

  listTenantAudit(tenantId: string, beforeId: number | undefined, limit: number) {
    return this.uow.repos.audit.list({ tenantId, beforeId, limit });
  }
}
