// Use case phân quyền: thu thập dữ kiện từ DB rồi áp dụng quy tắc (hàm decide thuần — test đơn vị được).
import type { Authorizer, AuthzDecision, AuthzInput } from '@ol/node-kit';
import { parsePrincipal, tenantOf } from '../domain/resource.js';
import type { AuthzFacts, UnitOfWork } from './ports.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// QUY TẮC PHÂN QUYỀN — thứ tự kiểm tra quan trọng; mặc định là TỪ CHỐI
export function decide(
  f: AuthzFacts,
  principalType: 'user' | 'group' | 'service',
  isTenantResource: boolean,
): Pick<AuthzDecision, 'allow' | 'reason'> {
  if (!f.permissionExists) return { allow: false, reason: 'unknown-permission' };
  if (principalType === 'group') return { allow: false, reason: 'no-binding' }; // Nhóm không tự gọi API
  if (principalType === 'user') {
    if (f.userStatus !== 'active') return { allow: false, reason: 'principal-disabled' };
    if (isTenantResource) {
      if (f.membershipStatus === null) return { allow: false, reason: 'not-member' };
      if (f.membershipStatus === 'disabled') return { allow: false, reason: 'membership-disabled' };
    }
    if (f.permissionRequiresMfa && !f.mfaEnrolled) return { allow: false, reason: 'mfa-required' };
  }
  if (isTenantResource && f.tenantStatus !== 'active') {
    return { allow: false, reason: f.tenantStatus === 'suspended' ? 'tenant-suspended' : 'no-binding' };
  }
  if (!f.bindingId) return { allow: false, reason: 'no-binding' };
  return { allow: true, reason: 'binding' };
}

export class AuthzService implements Authorizer {
  private readonly uow: UnitOfWork;
  constructor(deps: { uow: UnitOfWork }) {
    this.uow = deps.uow;
  }

  async check(input: AuthzInput): Promise<AuthzDecision> {
    const p = parsePrincipal(input.principal);
    const tenantId = tenantOf(input.resource);
    // Tenant id không phải UUID thì chắc chắn không tồn tại → từ chối, không chạy SQL
    if (tenantId !== null && !UUID.test(tenantId)) return { allow: false, reason: 'no-binding', policyVersion: 0 };
    if (p.type === 'user' && !UUID.test(p.id)) return { allow: false, reason: 'principal-disabled', policyVersion: 0 };
    const facts = await this.uow.repos.authz.facts({
      principalType: p.type,
      principalId: p.id,
      permission: input.permission,
      resource: input.resource,
      tenantId,
    });
    return { ...decide(facts, p.type, tenantId !== null), policyVersion: facts.policyVersion };
  }

  // Danh sách permission hiệu lực tại một resource — frontend dùng để ẩn/hiện nút
  async effectivePermissions(principal: string, resource: string): Promise<string[]> {
    const p = parsePrincipal(principal);
    const tenantId = tenantOf(resource);
    if (tenantId !== null && !UUID.test(tenantId)) return [];
    if (p.type === 'user' && tenantId !== null) {
      const m = await this.uow.repos.memberships.get(tenantId, p.id);
      if (m?.status !== 'active') return [];
    }
    return this.uow.repos.authz.effectivePermissions({ principalType: p.type, principalId: p.id, resource, tenantId });
  }
}
