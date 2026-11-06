// /v1/me: BFF gọi ngay sau khi người dùng đăng nhập.
// Đồng bộ hồ sơ từ token, chuyển trạng thái invited → active, cập nhật trạng thái MFA từ Keycloak,
// và trả danh sách tenant người dùng được vào.
import { ForbiddenError, type Principal } from '@ol/node-kit';
import { PLATFORM } from '../domain/resource.js';
import { audit } from './audit.js';
import type { AuthzService } from './authz-service.js';
import type { IdentityProvider, UnitOfWork } from './ports.js';

export class MeService {
  private readonly uow: UnitOfWork;
  private readonly idp: IdentityProvider;
  private readonly authzService: AuthzService;

  constructor(deps: { uow: UnitOfWork; idp: IdentityProvider; authzService: AuthzService }) {
    this.uow = deps.uow;
    this.idp = deps.idp;
    this.authzService = deps.authzService;
  }

  async get(principal: Principal, requestId?: string) {
    if (principal.type !== 'user') throw new ForbiddenError('Chỉ dành cho người dùng');
    const userId = principal.subject;
    const mfaEnrolled = await this.idp.hasOtp(userId); // Gọi Keycloak NGOÀI transaction

    const user = await this.uow.run(async (r) => {
      let u = await r.users.findById(userId);
      if (!u) {
        // Người dùng có trong Keycloak nhưng chưa có trong IAM (ví dụ admin realm tự tạo) — tạo hồ sơ, KHÔNG cấp quyền gì
        if (!principal.email) throw new ForbiddenError('Token không có email');
        u = await r.users.insert({ id: userId, email: principal.email, displayName: principal.name ?? null, status: 'active' });
        await audit(r, { id: principal.id, requestId }, { tenantId: null, action: 'iam.user.firstLogin', resource: `users/${userId}` });
      }
      const patch: Parameters<typeof r.users.update>[1] = { lastLoginAt: new Date(), mfaEnrolled };
      if (u.status === 'invited') patch.status = 'active'; // Lần đăng nhập đầu tiên sau khi được mời
      if (principal.name && principal.name !== u.displayName) patch.displayName = principal.name;
      await r.users.update(userId, patch);
      if (u.status === 'invited') {
        for (const inv of await r.invitations.findPendingByUser(userId)) await r.invitations.markAccepted(inv.id);
      }
      return { ...u, ...patch };
    });

    const tenants = (await this.uow.repos.memberships.listTenantsOfUser(userId)).filter(
      (t) => t.membershipStatus === 'active' && t.status === 'active',
    );
    const platformPermissions = await this.authzService.effectivePermissions(principal.id, PLATFORM);

    return {
      user: { id: user.id, email: user.email, displayName: user.displayName, status: user.status, mfaEnrolled: user.mfaEnrolled },
      tenants: tenants.map((t) => ({ id: t.id, slug: t.slug, name: t.name })),
      platform: { permissions: platformPermissions },
    };
  }
}
