// Use case về người dùng: mời, thu hồi lời mời, vô hiệu hóa/kích hoạt, đặt lại mật khẩu,
// và các thao tác cấp platform (khóa toàn cục, đăng xuất mọi phiên, đặt lại MFA).
import { ConflictError, NotFoundError, ValidationError } from '@ol/node-kit';
import { requiresMfa } from '../domain/catalog.js';
import { PLATFORM, tenantResource } from '../domain/resource.js';
import type { Actor, Invitation } from '../domain/types.js';
import { audit } from './audit.js';
import type { IdentityProvider, Repositories, UnitOfWork } from './ports.js';

const INVITE_TTL_SECONDS = 72 * 3600; // Link trong email mời có hiệu lực 72 giờ

export interface PreparedInvite {
  email: string;
  userId: string;
  isNewLocalUser: boolean;
  createdInIdp: boolean;
  needsMfa: boolean;
  roleIds: string[];
}

export class UserService {
  private readonly uow: UnitOfWork;
  private readonly idp: IdentityProvider;

  constructor(deps: { uow: UnitOfWork; idp: IdentityProvider }) {
    this.uow = deps.uow;
    this.idp = deps.idp;
  }

  listMembers(tenantId: string) {
    return this.uow.repos.memberships.listMembers(tenantId);
  }

  listInvitations(tenantId: string): Promise<Invitation[]> {
    return this.uow.repos.invitations.list(tenantId);
  }

  // Bước 1 (ngoài transaction): bảo đảm người dùng tồn tại trong Identity Provider
  async prepareInvite(email: string, roleIds: string[], mfaRoles: boolean): Promise<PreparedInvite> {
    const normalized = email.trim().toLowerCase();
    const local = await this.uow.repos.users.findByEmail(normalized);
    if (local?.status === 'disabled') throw new ConflictError('Người dùng đang bị khóa trên toàn platform');
    if (local) {
      return { email: normalized, userId: local.id, isNewLocalUser: false, createdInIdp: false, needsMfa: mfaRoles, roleIds };
    }
    const existing = await this.idp.findUserByEmail(normalized);
    if (existing) {
      return { email: normalized, userId: existing.id, isNewLocalUser: true, createdInIdp: false, needsMfa: mfaRoles, roleIds };
    }
    const requiredActions = ['UPDATE_PASSWORD', 'VERIFY_EMAIL', ...(mfaRoles ? ['CONFIGURE_TOTP'] : [])];
    const userId = await this.idp.createUser({ email: normalized, requiredActions });
    return { email: normalized, userId, isNewLocalUser: true, createdInIdp: true, needsMfa: mfaRoles, roleIds };
  }

  // Bước 2 (trong transaction): user, membership, binding, lời mời, audit
  async persistInvite(r: Repositories, actor: Actor, tenantId: string, prep: PreparedInvite): Promise<Invitation> {
    if (prep.isNewLocalUser) {
      await r.users.insert({ id: prep.userId, email: prep.email, displayName: null, status: 'invited' });
    }
    const existing = await r.memberships.get(tenantId, prep.userId);
    if (existing) throw new ConflictError('Người dùng đã là thành viên của tenant');
    await r.memberships.add(tenantId, prep.userId);
    for (const roleId of prep.roleIds) {
      await r.bindings.create({
        tenantId,
        principalType: 'user',
        principalId: prep.userId,
        roleId,
        resource: tenantResource(tenantId),
        createdBy: actor.id,
        expiresAt: null,
      });
    }
    const invitation = await r.invitations.create({
      tenantId,
      email: prep.email,
      roleIds: prep.roleIds,
      invitedBy: actor.id,
      userId: prep.userId,
      expiresAt: new Date(Date.now() + INVITE_TTL_SECONDS * 1000),
    });
    await audit(r, actor, {
      tenantId,
      action: 'iam.user.invited',
      resource: `${tenantResource(tenantId)}/users/${prep.userId}`,
      details: { email: prep.email, roleIds: prep.roleIds },
    });
    return invitation;
  }

  // Bước 3 (sau commit): gửi email; lỗi gửi email không làm mất dữ liệu đã lưu
  async afterInvite(prep: PreparedInvite): Promise<void> {
    if (prep.createdInIdp) {
      await this.idp.sendActionsEmail(
        prep.userId,
        ['UPDATE_PASSWORD', 'VERIFY_EMAIL', ...(prep.needsMfa ? ['CONFIGURE_TOTP'] : [])],
        INVITE_TTL_SECONDS,
      );
    } else if (prep.needsMfa && !(await this.idp.hasOtp(prep.userId))) {
      await this.idp.addRequiredActions(prep.userId, ['CONFIGURE_TOTP']);
    }
  }

  async invite(actor: Actor, tenantId: string, input: { email: string; roleIds: string[] }): Promise<Invitation> {
    const roles = await this.assertAssignableRoles(tenantId, input.roleIds);
    const prep = await this.prepareInvite(input.email, input.roleIds, requiresMfa(roles.flatMap((x) => x.permissions)));
    const invitation = await this.uow.run((r) => this.persistInvite(r, actor, tenantId, prep));
    await this.afterInvite(prep);
    return invitation;
  }

  async assertAssignableRoles(tenantId: string, roleIds: string[]) {
    if (roleIds.length === 0) throw new ValidationError('Cần ít nhất một role');
    const assignable = await this.uow.repos.roles.listAssignable(tenantId);
    const found = roleIds.map((id) => assignable.find((x) => x.id === id));
    const missing = roleIds.filter((_, i) => !found[i]);
    if (missing.length > 0) throw new ValidationError('Role không gán được trong tenant', { roleIds: missing });
    return found.filter((x) => x !== undefined);
  }

  async revokeInvitation(actor: Actor, tenantId: string, invitationId: string): Promise<void> {
    await this.uow.run(async (r) => {
      const inv = await r.invitations.revoke(tenantId, invitationId);
      if (!inv) throw new NotFoundError('Không có lời mời đang chờ với id này');
      if (inv.userId) {
        const user = await r.users.findById(inv.userId);
        // Người được mời chưa từng đăng nhập → gỡ membership và quyền đã tạo kèm lời mời
        if (user?.status === 'invited') {
          await r.bindings.deleteForPrincipal(tenantId, 'user', inv.userId);
          await r.memberships.remove(tenantId, inv.userId);
        }
      }
      await audit(r, actor, {
        tenantId,
        action: 'iam.invitation.revoked',
        resource: `${tenantResource(tenantId)}/invitations/${invitationId}`,
        details: { email: inv.email },
      });
    });
  }

  async setMembershipStatus(actor: Actor, tenantId: string, userId: string, status: 'active' | 'disabled'): Promise<void> {
    if (actor.id === `users/${userId}`) throw new ValidationError('Không thể tự thay đổi trạng thái của chính mình');
    await this.uow.run(async (r) => {
      const ok = await r.memberships.setStatus(tenantId, userId, status);
      if (!ok) throw new NotFoundError('Người dùng không thuộc tenant');
      await audit(r, actor, {
        tenantId,
        action: status === 'disabled' ? 'iam.user.disabled' : 'iam.user.enabled',
        resource: `${tenantResource(tenantId)}/users/${userId}`,
      });
    });
  }

  async resetPassword(actor: Actor, tenantId: string, userId: string): Promise<void> {
    const m = await this.uow.repos.memberships.get(tenantId, userId);
    if (!m) throw new NotFoundError('Người dùng không thuộc tenant');
    await this.idp.sendActionsEmail(userId, ['UPDATE_PASSWORD'], 24 * 3600);
    await this.uow.run((r) =>
      audit(r, actor, { tenantId, action: 'iam.user.passwordResetRequested', resource: `${tenantResource(tenantId)}/users/${userId}` }),
    );
  }

  // ---- Thao tác cấp platform ----
  async setGlobalStatus(actor: Actor, userId: string, enabled: boolean): Promise<void> {
    if (actor.id === `users/${userId}`) throw new ValidationError('Không thể tự khóa chính mình');
    const user = await this.uow.repos.users.findById(userId);
    if (!user) throw new NotFoundError('Không tìm thấy người dùng');
    await this.idp.setEnabled(userId, enabled);
    if (!enabled) await this.idp.logout(userId); // Hủy mọi phiên ngay → BFF nhận back-channel logout
    await this.uow.run(async (r) => {
      await r.users.update(userId, { status: enabled ? 'active' : 'disabled' });
      await audit(r, actor, { tenantId: null, action: enabled ? 'platform.user.enabled' : 'platform.user.disabled', resource: `${PLATFORM}/users/${userId}` });
    });
  }

  async logoutEverywhere(actor: Actor, userId: string): Promise<void> {
    await this.idp.logout(userId);
    await this.uow.run((r) => audit(r, actor, { tenantId: null, action: 'platform.user.loggedOut', resource: `${PLATFORM}/users/${userId}` }));
  }

  async resetMfa(actor: Actor, userId: string): Promise<void> {
    await this.idp.removeOtp(userId);
    await this.idp.addRequiredActions(userId, ['CONFIGURE_TOTP']);
    await this.idp.logout(userId);
    await this.uow.run(async (r) => {
      await r.users.update(userId, { mfaEnrolled: false });
      await audit(r, actor, { tenantId: null, action: 'platform.user.mfaReset', resource: `${PLATFORM}/users/${userId}` });
    });
  }
}
