// Use case role và gán quyền (role binding).
import { ConflictError, NotFoundError, ValidationError } from '@ol/node-kit';
import { PERMISSION_BY_NAME, requiresMfa } from '../domain/catalog.js';
import { isValidResource, isWithin, tenantResource } from '../domain/resource.js';
import type { Actor, PrincipalType } from '../domain/types.js';
import { audit } from './audit.js';
import type { IdentityProvider, UnitOfWork } from './ports.js';

const ROLE_NAME = /^[a-zA-Z][a-zA-Z0-9]{2,40}$/;

export class RoleService {
  private readonly uow: UnitOfWork;
  private readonly idp: IdentityProvider;

  constructor(deps: { uow: UnitOfWork; idp: IdentityProvider }) {
    this.uow = deps.uow;
    this.idp = deps.idp;
  }

  async listTenantPermissions() {
    return (await this.uow.repos.roles.listPermissions()).filter((p) => p.assignable === 'tenant');
  }

  listRoles(tenantId: string) {
    return this.uow.repos.roles.listAssignable(tenantId);
  }

  createCustomRole(actor: Actor, tenantId: string, input: { name: string; title: string; description?: string | null; permissions: string[] }) {
    if (!ROLE_NAME.test(input.name)) throw new ValidationError('Tên role: chữ cái đầu, 3–41 ký tự chữ/số');
    const unique = Array.from(new Set(input.permissions));
    if (unique.length === 0) throw new ValidationError('Role cần ít nhất một permission');
    // Chỉ cho phép permission loại "tenant" — không thể tự tạo role có quyền platform/service
    const invalid = unique.filter((p) => PERMISSION_BY_NAME.get(p)?.assignable !== 'tenant');
    if (invalid.length > 0) throw new ValidationError('Permission không dùng được trong role tùy chỉnh', { permissions: invalid });
    const id = `${tenantResource(tenantId)}/roles/${input.name}`;
    return this.uow.run(async (r) => {
      const role = await r.roles.createCustom({ tenantId, id, title: input.title, description: input.description ?? null, permissions: unique });
      await audit(r, actor, { tenantId, action: 'iam.role.created', resource: id, details: { permissions: unique } });
      return role;
    });
  }

  deleteCustomRole(actor: Actor, tenantId: string, name: string) {
    const id = `${tenantResource(tenantId)}/roles/${name}`;
    return this.uow.run(async (r) => {
      if (!(await r.roles.deleteCustom(tenantId, id))) throw new NotFoundError('Không tìm thấy role tùy chỉnh');
      await audit(r, actor, { tenantId, action: 'iam.role.deleted', resource: id });
    });
  }

  listBindings(tenantId: string) {
    return this.uow.repos.bindings.list(tenantId);
  }

  async createBinding(
    actor: Actor,
    tenantId: string,
    input: { principalType: Exclude<PrincipalType, 'service'>; principalId: string; roleId: string; resource: string; expiresAt?: Date | null },
  ) {
    // Phạm vi phải nằm trong cây tài nguyên của tenant này
    if (!isValidResource(input.resource) || !isWithin(input.resource, tenantResource(tenantId))) {
      throw new ValidationError('Resource phải nằm trong tenant hiện tại');
    }
    const role = (await this.uow.repos.roles.listAssignable(tenantId)).find((x) => x.id === input.roleId);
    if (!role) throw new ValidationError('Role không gán được trong tenant');

    const binding = await this.uow.run(async (r) => {
      if (input.principalType === 'user') {
        if (!(await r.memberships.get(tenantId, input.principalId))) throw new ValidationError('Người dùng không thuộc tenant');
      } else if (!(await r.groups.get(tenantId, input.principalId))) {
        throw new ValidationError('Nhóm không thuộc tenant');
      }
      const b = await r.bindings.create({
        tenantId,
        principalType: input.principalType,
        principalId: input.principalId,
        roleId: input.roleId,
        resource: input.resource,
        createdBy: actor.id,
        expiresAt: input.expiresAt ?? null,
      });
      await audit(r, actor, { tenantId, action: 'iam.roleBinding.created', resource: input.resource, details: { bindingId: b.id, roleId: b.roleId, principal: `${b.principalType}s/${b.principalId}` } });
      return b;
    });

    // Role quản trị cần MFA → yêu cầu người dùng đăng ký TOTP ở lần đăng nhập tới
    if (input.principalType === 'user' && requiresMfa(role.permissions) && !(await this.idp.hasOtp(input.principalId))) {
      await this.idp.addRequiredActions(input.principalId, ['CONFIGURE_TOTP']);
    }
    return binding;
  }

  deleteBinding(actor: Actor, tenantId: string, bindingId: string) {
    return this.uow.run(async (r) => {
      const b = await r.bindings.get(tenantId, bindingId);
      if (!b) throw new NotFoundError('Không tìm thấy binding');
      // An toàn: không cho gỡ quản trị viên cuối cùng của tenant (tránh tenant "mồ côi")
      if (b.roleId === 'roles/iam.tenantAdmin' && b.resource === tenantResource(tenantId)) {
        if ((await r.bindings.countForRole(b.roleId, b.resource)) <= 1) {
          throw new ConflictError('Không thể gỡ quản trị viên cuối cùng của tenant');
        }
      }
      await r.bindings.delete(tenantId, bindingId);
      await audit(r, actor, { tenantId, action: 'iam.roleBinding.deleted', resource: b.resource, details: { bindingId, roleId: b.roleId, principal: `${b.principalType}s/${b.principalId}` } });
    });
  }
}
