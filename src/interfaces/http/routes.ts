// Khai báo toàn bộ API của IAM. Mỗi route: đường dẫn + policy (bắt buộc) + handler mỏng gọi use case.
// Handler KHÔNG chứa logic nghiệp vụ — chỉ chuyển dữ liệu HTTP ↔ use case.
import { AuthorizeRequestSchema, handle, policy, SecureRouter, type Principal } from '@ol/node-kit';
import type { Request } from 'express';
import { z } from 'zod';
import type { Cradle } from '../../container.js';
import { PLATFORM } from '../../domain/resource.js';
import type { Actor } from '../../domain/types.js';

const tenant = (p: Record<string, string>) => `tenants/${p.tenantId}`;
const platform = () => PLATFORM;

const TenantParams = z.object({ tenantId: z.uuid() });
const TenantUserParams = TenantParams.extend({ userId: z.uuid() });
const GroupParams = TenantParams.extend({ groupId: z.uuid() });
const GroupMemberParams = GroupParams.extend({ userId: z.uuid() });
const UserParams = z.object({ userId: z.uuid() });
const AuditQuery = z.object({
  before: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

function actorOf(principal: Principal, req: Request): Actor {
  return { id: principal.id, requestId: req.requestId, ip: req.ip };
}

export function buildRoutes(c: Cradle): SecureRouter {
  const r = new SecureRouter({ verifier: c.tokenVerifier, authorizer: c.authorizer, logger: c.logger });

  // ---------------- Người dùng hiện tại ----------------
  r.get('/v1/me', policy.authenticated(), handle({}, ({ principal, req }) => c.meService.get(principal, req.requestId)));

  r.get(
    '/v1/me/permissions',
    policy.authenticated(),
    handle({ query: z.object({ resource: z.string().max(1024) }) }, async ({ principal, query }) => ({
      resource: query.resource,
      permissions: await c.authzService.effectivePermissions(principal.id, query.resource),
    })),
  );

  r.get('/v1/permissions', policy.authenticated(), handle({}, () => c.roleService.listTenantPermissions()));

  // ---------------- Platform ----------------
  r.get('/v1/tenants', policy.permission('platform.tenants.list', platform), handle({}, () => c.tenantService.list()));

  r.post(
    '/v1/tenants',
    policy.permission('platform.tenants.create', platform),
    handle(
      {
        body: z.object({
          slug: z.string().regex(/^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/),
          name: z.string().min(1).max(200),
          adminEmail: z.email(),
        }),
      },
      ({ body, principal, req }) => c.tenantService.create(actorOf(principal, req), body),
      { status: 201 },
    ),
  );

  r.get(
    '/v1/platform/audit-events',
    policy.permission('platform.audit.list', platform),
    handle({ query: AuditQuery }, ({ query }) => c.tenantService.listPlatformAudit(query.before, query.limit)),
  );

  r.post('/v1/users/:userId/disable', policy.permission('platform.users.disable', platform),
    handle({ params: UserParams }, ({ params, principal, req }) => c.userService.setGlobalStatus(actorOf(principal, req), params.userId, false)));
  r.post('/v1/users/:userId/enable', policy.permission('platform.users.disable', platform),
    handle({ params: UserParams }, ({ params, principal, req }) => c.userService.setGlobalStatus(actorOf(principal, req), params.userId, true)));
  r.post('/v1/users/:userId/logout', policy.permission('platform.users.logout', platform),
    handle({ params: UserParams }, ({ params, principal, req }) => c.userService.logoutEverywhere(actorOf(principal, req), params.userId)));
  r.post('/v1/users/:userId/reset-mfa', policy.permission('platform.users.resetMfa', platform),
    handle({ params: UserParams }, ({ params, principal, req }) => c.userService.resetMfa(actorOf(principal, req), params.userId)));

  // ---------------- Tenant ----------------
  r.get('/v1/tenants/:tenantId', policy.permission('iam.tenants.get', tenant),
    handle({ params: TenantParams }, ({ params }) => c.tenantService.get(params.tenantId)));

  // ---------------- Người dùng trong tenant ----------------
  r.get('/v1/tenants/:tenantId/users', policy.permission('iam.users.list', tenant),
    handle({ params: TenantParams }, ({ params }) => c.userService.listMembers(params.tenantId)));

  r.get('/v1/tenants/:tenantId/invitations', policy.permission('iam.users.list', tenant),
    handle({ params: TenantParams }, ({ params }) => c.userService.listInvitations(params.tenantId)));

  r.post(
    '/v1/tenants/:tenantId/invitations',
    policy.permission('iam.users.invite', tenant),
    handle(
      { params: TenantParams, body: z.object({ email: z.email(), roleIds: z.array(z.string().max(300)).min(1).max(20) }) },
      ({ params, body, principal, req }) => c.userService.invite(actorOf(principal, req), params.tenantId, body),
      { status: 201 },
    ),
  );

  r.delete(
    '/v1/tenants/:tenantId/invitations/:invitationId',
    policy.permission('iam.users.invite', tenant),
    handle({ params: TenantParams.extend({ invitationId: z.uuid() }) }, ({ params, principal, req }) =>
      c.userService.revokeInvitation(actorOf(principal, req), params.tenantId, params.invitationId)),
  );

  r.post('/v1/tenants/:tenantId/users/:userId/disable', policy.permission('iam.users.disable', tenant),
    handle({ params: TenantUserParams }, ({ params, principal, req }) =>
      c.userService.setMembershipStatus(actorOf(principal, req), params.tenantId, params.userId, 'disabled')));
  r.post('/v1/tenants/:tenantId/users/:userId/enable', policy.permission('iam.users.enable', tenant),
    handle({ params: TenantUserParams }, ({ params, principal, req }) =>
      c.userService.setMembershipStatus(actorOf(principal, req), params.tenantId, params.userId, 'active')));
  r.post('/v1/tenants/:tenantId/users/:userId/reset-password', policy.permission('iam.users.resetPassword', tenant),
    handle({ params: TenantUserParams }, ({ params, principal, req }) =>
      c.userService.resetPassword(actorOf(principal, req), params.tenantId, params.userId)));

  // ---------------- Nhóm ----------------
  r.get('/v1/tenants/:tenantId/groups', policy.permission('iam.groups.list', tenant),
    handle({ params: TenantParams }, ({ params }) => c.groupService.list(params.tenantId)));

  r.post(
    '/v1/tenants/:tenantId/groups',
    policy.permission('iam.groups.create', tenant),
    handle(
      { params: TenantParams, body: z.object({ name: z.string().regex(/^[A-Za-z0-9 ._-]{2,64}$/), description: z.string().max(500).nullish() }) },
      ({ params, body, principal, req }) => c.groupService.create(actorOf(principal, req), params.tenantId, body),
      { status: 201 },
    ),
  );

  r.delete('/v1/tenants/:tenantId/groups/:groupId', policy.permission('iam.groups.delete', tenant),
    handle({ params: GroupParams }, ({ params, principal, req }) => c.groupService.delete(actorOf(principal, req), params.tenantId, params.groupId)));

  r.get('/v1/tenants/:tenantId/groups/:groupId/members', policy.permission('iam.groups.list', tenant),
    handle({ params: GroupParams }, ({ params }) => c.groupService.listMembers(params.tenantId, params.groupId)));

  r.put('/v1/tenants/:tenantId/groups/:groupId/members/:userId', policy.permission('iam.groups.manageMembers', tenant),
    handle({ params: GroupMemberParams }, ({ params, principal, req }) =>
      c.groupService.addMember(actorOf(principal, req), params.tenantId, params.groupId, params.userId)));

  r.delete('/v1/tenants/:tenantId/groups/:groupId/members/:userId', policy.permission('iam.groups.manageMembers', tenant),
    handle({ params: GroupMemberParams }, ({ params, principal, req }) =>
      c.groupService.removeMember(actorOf(principal, req), params.tenantId, params.groupId, params.userId)));

  // ---------------- Role ----------------
  r.get('/v1/tenants/:tenantId/roles', policy.permission('iam.roles.list', tenant),
    handle({ params: TenantParams }, ({ params }) => c.roleService.listRoles(params.tenantId)));

  r.post(
    '/v1/tenants/:tenantId/roles',
    policy.permission('iam.roles.create', tenant),
    handle(
      {
        params: TenantParams,
        body: z.object({
          name: z.string(),
          title: z.string().min(1).max(100),
          description: z.string().max(500).nullish(),
          permissions: z.array(z.string()).min(1).max(100),
        }),
      },
      ({ params, body, principal, req }) => c.roleService.createCustomRole(actorOf(principal, req), params.tenantId, body),
      { status: 201 },
    ),
  );

  r.delete('/v1/tenants/:tenantId/roles/:roleName', policy.permission('iam.roles.delete', tenant),
    handle({ params: TenantParams.extend({ roleName: z.string().regex(/^[a-zA-Z][a-zA-Z0-9]{2,40}$/) }) }, ({ params, principal, req }) =>
      c.roleService.deleteCustomRole(actorOf(principal, req), params.tenantId, params.roleName)));

  // ---------------- Gán quyền ----------------
  r.get('/v1/tenants/:tenantId/role-bindings', policy.permission('iam.roleBindings.list', tenant),
    handle({ params: TenantParams }, ({ params }) => c.roleService.listBindings(params.tenantId)));

  r.post(
    '/v1/tenants/:tenantId/role-bindings',
    policy.permission('iam.roleBindings.create', tenant),
    handle(
      {
        params: TenantParams,
        body: z.object({
          principalType: z.enum(['user', 'group']),
          principalId: z.uuid(),
          roleId: z.string().max(300),
          resource: z.string().max(1024),
          expiresAt: z.coerce.date().nullish(),
        }),
      },
      ({ params, body, principal, req }) => c.roleService.createBinding(actorOf(principal, req), params.tenantId, body),
      { status: 201 },
    ),
  );

  r.delete('/v1/tenants/:tenantId/role-bindings/:bindingId', policy.permission('iam.roleBindings.delete', tenant),
    handle({ params: TenantParams.extend({ bindingId: z.uuid() }) }, ({ params, principal, req }) =>
      c.roleService.deleteBinding(actorOf(principal, req), params.tenantId, params.bindingId)));

  // ---------------- Audit ----------------
  r.get('/v1/tenants/:tenantId/audit-events', policy.permission('iam.audit.list', tenant),
    handle({ params: TenantParams, query: AuditQuery }, ({ params, query }) =>
      c.tenantService.listTenantAudit(params.tenantId, query.before, query.limit)));

  // ---------------- Nội bộ: API quyết định phân quyền cho service khác ----------------
  // Không có route tương ứng trên BFF/ALB; chỉ service có role iam.authzChecker gọi được
  r.post(
    '/internal/v1/authorize',
    policy.permission('iam.authz.check', platform),
    handle({ body: AuthorizeRequestSchema }, ({ body }) => c.authzService.check(body)),
  );

  return r;
}
