// Hiện thực các repository bằng Drizzle ORM + PostgreSQL.
// Mỗi repository nhận một "Db" — có thể là kết nối thường hoặc transaction (Unit of Work).
import { and, count, desc, eq, inArray, isNull, lt, or, sql } from 'drizzle-orm';
import type { NodePgQueryResultHKT } from 'drizzle-orm/node-postgres';
import type { PgDatabase } from 'drizzle-orm/pg-core';
import { ConflictError } from '@ol/node-kit';
import type { PermissionDef, RoleDef } from '../../domain/catalog.js';
import type { Role } from '../../domain/types.js';
import type {
  AuditRepository,
  AuthzFacts,
  AuthzRepository,
  BindingRepository,
  GroupRepository,
  InvitationRepository,
  MembershipRepository,
  Repositories,
  RoleRepository,
  TenantRepository,
  UserRepository,
} from '../../application/ports.js';
import {
  auditEvents,
  groupMembers,
  groups,
  invitations,
  memberships,
  permissions,
  roleBindings,
  rolePermissions,
  roles,
  schema,
  tenants,
  users,
} from './schema.js';

export type Db = PgDatabase<NodePgQueryResultHKT, typeof schema>;

// Mã lỗi PostgreSQL: 23505 = vi phạm UNIQUE, 23503 = vi phạm khóa ngoại
function pgCode(err: unknown): string | undefined {
  const e = err as { code?: string; cause?: { code?: string } };
  return e?.code ?? e?.cause?.code;
}
async function mapConflict<T>(p: Promise<T>, message: string): Promise<T> {
  try {
    return await p;
  } catch (err) {
    const code = pgCode(err);
    if (code === '23505' || code === '23503') throw new ConflictError(message);
    throw err;
  }
}

class DrizzleTenantRepository implements TenantRepository {
  constructor(private readonly db: Db) {}
  async create(input: { slug: string; name: string }) {
    const [row] = await mapConflict(this.db.insert(tenants).values(input).returning(), 'Slug tenant đã tồn tại');
    return row!;
  }
  async findById(id: string) {
    const [row] = await this.db.select().from(tenants).where(eq(tenants.id, id));
    return row ?? null;
  }
  async findBySlug(slug: string) {
    const [row] = await this.db.select().from(tenants).where(eq(tenants.slug, slug));
    return row ?? null;
  }
  list() {
    return this.db.select().from(tenants).orderBy(tenants.name);
  }
}

class DrizzleUserRepository implements UserRepository {
  constructor(private readonly db: Db) {}
  async findById(id: string) {
    const [row] = await this.db.select().from(users).where(eq(users.id, id));
    return row ?? null;
  }
  async findByEmail(email: string) {
    const [row] = await this.db.select().from(users).where(eq(users.email, email.toLowerCase()));
    return row ?? null;
  }
  async insert(input: { id: string; email: string; displayName: string | null; status: 'invited' | 'active' | 'disabled' }) {
    const [row] = await mapConflict(
      this.db.insert(users).values({ ...input, email: input.email.toLowerCase() }).returning(),
      'Email đã được dùng bởi người dùng khác',
    );
    return row!;
  }
  async update(id: string, patch: Parameters<UserRepository['update']>[1]) {
    if (Object.keys(patch).length === 0) return;
    await this.db.update(users).set(patch).where(eq(users.id, id));
  }
}

class DrizzleMembershipRepository implements MembershipRepository {
  constructor(private readonly db: Db) {}
  async add(tenantId: string, userId: string) {
    await this.db.insert(memberships).values({ tenantId, userId }).onConflictDoNothing();
  }
  async remove(tenantId: string, userId: string) {
    const rows = await this.db
      .delete(memberships)
      .where(and(eq(memberships.tenantId, tenantId), eq(memberships.userId, userId)))
      .returning({ userId: memberships.userId });
    return rows.length > 0;
  }
  async get(tenantId: string, userId: string) {
    const [row] = await this.db
      .select({ status: memberships.status })
      .from(memberships)
      .where(and(eq(memberships.tenantId, tenantId), eq(memberships.userId, userId)));
    return row ?? null;
  }
  async setStatus(tenantId: string, userId: string, status: 'active' | 'disabled') {
    const rows = await this.db
      .update(memberships)
      .set({ status })
      .where(and(eq(memberships.tenantId, tenantId), eq(memberships.userId, userId)))
      .returning({ userId: memberships.userId });
    return rows.length > 0;
  }
  async listMembers(tenantId: string) {
    const rows = await this.db
      .select({ user: users, membershipStatus: memberships.status })
      .from(memberships)
      .innerJoin(users, eq(users.id, memberships.userId))
      .where(eq(memberships.tenantId, tenantId))
      .orderBy(users.email);
    return rows.map((r) => ({ ...r.user, membershipStatus: r.membershipStatus }));
  }
  async listTenantsOfUser(userId: string) {
    const rows = await this.db
      .select({ tenant: tenants, membershipStatus: memberships.status })
      .from(memberships)
      .innerJoin(tenants, eq(tenants.id, memberships.tenantId))
      .where(eq(memberships.userId, userId))
      .orderBy(tenants.name);
    return rows.map((r) => ({ ...r.tenant, membershipStatus: r.membershipStatus }));
  }
}

class DrizzleGroupRepository implements GroupRepository {
  constructor(private readonly db: Db) {}
  async list(tenantId: string) {
    const rows = await this.db
      .select({ group: groups, memberCount: count(groupMembers.userId) })
      .from(groups)
      .leftJoin(groupMembers, eq(groupMembers.groupId, groups.id))
      .where(eq(groups.tenantId, tenantId))
      .groupBy(groups.id)
      .orderBy(groups.name);
    return rows.map((r) => ({ ...r.group, memberCount: Number(r.memberCount) }));
  }
  async get(tenantId: string, groupId: string) {
    const [row] = await this.db.select().from(groups).where(and(eq(groups.tenantId, tenantId), eq(groups.id, groupId)));
    return row ?? null;
  }
  async create(input: { tenantId: string; name: string; description: string | null }) {
    const [row] = await mapConflict(this.db.insert(groups).values(input).returning(), 'Tên nhóm đã tồn tại');
    return row!;
  }
  async delete(tenantId: string, groupId: string) {
    // Xóa luôn binding gán cho nhóm để không còn binding "mồ côi"
    await this.db
      .delete(roleBindings)
      .where(and(eq(roleBindings.tenantId, tenantId), eq(roleBindings.principalType, 'group'), eq(roleBindings.principalId, groupId)));
    const rows = await this.db
      .delete(groups)
      .where(and(eq(groups.tenantId, tenantId), eq(groups.id, groupId)))
      .returning({ id: groups.id });
    return rows.length > 0;
  }
  async listMembers(tenantId: string, groupId: string) {
    const rows = await this.db
      .select({ user: users })
      .from(groupMembers)
      .innerJoin(users, eq(users.id, groupMembers.userId))
      .where(and(eq(groupMembers.tenantId, tenantId), eq(groupMembers.groupId, groupId)))
      .orderBy(users.email);
    return rows.map((r) => r.user);
  }
  async addMember(tenantId: string, groupId: string, userId: string) {
    // Khóa ngoại kép (tenant_id, user_id) → memberships: user không thuộc tenant sẽ bị DB từ chối
    await mapConflict(
      this.db.insert(groupMembers).values({ tenantId, groupId, userId }).onConflictDoNothing(),
      'Người dùng không thuộc tenant hoặc nhóm không tồn tại',
    );
  }
  async removeMember(tenantId: string, groupId: string, userId: string) {
    const rows = await this.db
      .delete(groupMembers)
      .where(and(eq(groupMembers.tenantId, tenantId), eq(groupMembers.groupId, groupId), eq(groupMembers.userId, userId)))
      .returning({ userId: groupMembers.userId });
    return rows.length > 0;
  }
}

class DrizzleRoleRepository implements RoleRepository {
  constructor(private readonly db: Db) {}

  private async withPermissions(rows: Array<typeof roles.$inferSelect>): Promise<Role[]> {
    if (rows.length === 0) return [];
    const perms = await this.db
      .select()
      .from(rolePermissions)
      .where(inArray(rolePermissions.roleId, rows.map((r) => r.id)));
    return rows.map((r) => ({
      id: r.id,
      tenantId: r.tenantId,
      title: r.title,
      description: r.description,
      isSystem: r.isSystem,
      assignable: r.assignable,
      permissions: perms.filter((p) => p.roleId === r.id).map((p) => p.permission).sort(),
    }));
  }

  async listAssignable(tenantId: string) {
    const rows = await this.db
      .select()
      .from(roles)
      .where(or(and(isNull(roles.tenantId), eq(roles.assignable, 'tenant')), eq(roles.tenantId, tenantId)))
      .orderBy(desc(roles.isSystem), roles.id);
    return this.withPermissions(rows);
  }

  async get(id: string) {
    const rows = await this.db.select().from(roles).where(eq(roles.id, id));
    const [role] = await this.withPermissions(rows);
    return role ?? null;
  }

  async createCustom(input: { tenantId: string; id: string; title: string; description: string | null; permissions: string[] }) {
    await mapConflict(
      this.db.insert(roles).values({
        id: input.id,
        tenantId: input.tenantId,
        title: input.title,
        description: input.description,
        isSystem: false,
        assignable: 'tenant',
      }),
      'Role đã tồn tại',
    );
    await this.db.insert(rolePermissions).values(input.permissions.map((permission) => ({ roleId: input.id, permission })));
    return (await this.get(input.id))!;
  }

  async deleteCustom(tenantId: string, id: string) {
    const rows = await mapConflict(
      this.db
        .delete(roles)
        .where(and(eq(roles.id, id), eq(roles.tenantId, tenantId), eq(roles.isSystem, false)))
        .returning({ id: roles.id }),
      'Role đang được gán, hãy thu hồi các binding trước',
    );
    return rows.length > 0;
  }

  async countBindings(roleId: string) {
    const [row] = await this.db.select({ n: count() }).from(roleBindings).where(eq(roleBindings.roleId, roleId));
    return Number(row?.n ?? 0);
  }

  // Đồng bộ danh mục từ code vào DB (idempotent): thêm/cập nhật permission và role hệ thống
  async syncCatalog(permDefs: PermissionDef[], roleDefs: RoleDef[]) {
    for (const p of permDefs) {
      await this.db
        .insert(permissions)
        .values({ name: p.name, description: p.description, assignable: p.assignable, requiresMfa: p.requiresMfa ?? false })
        .onConflictDoUpdate({
          target: permissions.name,
          set: { description: p.description, assignable: p.assignable, requiresMfa: p.requiresMfa ?? false },
        });
    }
    for (const r of roleDefs) {
      await this.db
        .insert(roles)
        .values({ id: r.id, title: r.title, description: r.description, isSystem: true, assignable: r.assignable })
        .onConflictDoUpdate({ target: roles.id, set: { title: r.title, description: r.description, assignable: r.assignable } });
      // Thay toàn bộ permission của role hệ thống bằng danh sách trong code
      await this.db.delete(rolePermissions).where(eq(rolePermissions.roleId, r.id));
      await this.db.insert(rolePermissions).values(r.permissions.map((permission) => ({ roleId: r.id, permission })));
    }
  }

  async listPermissions() {
    const rows = await this.db.select().from(permissions).orderBy(permissions.name);
    return rows.map((r) => ({ name: r.name, description: r.description, assignable: r.assignable, requiresMfa: r.requiresMfa }));
  }
}

class DrizzleBindingRepository implements BindingRepository {
  constructor(private readonly db: Db) {}
  list(tenantId: string) {
    return this.db.select().from(roleBindings).where(eq(roleBindings.tenantId, tenantId)).orderBy(roleBindings.resource, roleBindings.roleId);
  }
  async get(tenantId: string | null, id: string) {
    const [row] = await this.db
      .select()
      .from(roleBindings)
      .where(and(eq(roleBindings.id, id), tenantId === null ? isNull(roleBindings.tenantId) : eq(roleBindings.tenantId, tenantId)));
    return row ?? null;
  }
  async create(input: Parameters<BindingRepository['create']>[0]) {
    const [row] = await mapConflict(this.db.insert(roleBindings).values(input).returning(), 'Binding đã tồn tại');
    return row!;
  }
  async ensure(input: Parameters<BindingRepository['ensure']>[0]) {
    await this.db.insert(roleBindings).values(input).onConflictDoNothing();
  }
  async delete(tenantId: string | null, id: string) {
    const rows = await this.db
      .delete(roleBindings)
      .where(and(eq(roleBindings.id, id), tenantId === null ? isNull(roleBindings.tenantId) : eq(roleBindings.tenantId, tenantId)))
      .returning({ id: roleBindings.id });
    return rows.length > 0;
  }
  async deleteForPrincipal(tenantId: string, principalType: 'user' | 'group' | 'service', principalId: string) {
    const rows = await this.db
      .delete(roleBindings)
      .where(
        and(eq(roleBindings.tenantId, tenantId), eq(roleBindings.principalType, principalType), eq(roleBindings.principalId, principalId)),
      )
      .returning({ id: roleBindings.id });
    return rows.length;
  }
  async countForRole(roleId: string, resource: string) {
    const [row] = await this.db
      .select({ n: count() })
      .from(roleBindings)
      .where(and(eq(roleBindings.roleId, roleId), eq(roleBindings.resource, resource)));
    return Number(row?.n ?? 0);
  }
}

class DrizzleInvitationRepository implements InvitationRepository {
  constructor(private readonly db: Db) {}
  async create(input: Parameters<InvitationRepository['create']>[0]) {
    const [row] = await mapConflict(
      this.db.insert(invitations).values({ ...input, email: input.email.toLowerCase() }).returning(),
      'Email này đã có lời mời đang chờ',
    );
    return row!;
  }
  list(tenantId: string) {
    return this.db.select().from(invitations).where(eq(invitations.tenantId, tenantId)).orderBy(desc(invitations.createdAt));
  }
  async revoke(tenantId: string, id: string) {
    const [row] = await this.db
      .update(invitations)
      .set({ status: 'revoked' })
      .where(and(eq(invitations.tenantId, tenantId), eq(invitations.id, id), eq(invitations.status, 'pending')))
      .returning();
    return row ?? null;
  }
  findPendingByUser(userId: string) {
    return this.db.select().from(invitations).where(and(eq(invitations.userId, userId), eq(invitations.status, 'pending')));
  }
  async markAccepted(id: string) {
    await this.db.update(invitations).set({ status: 'accepted', acceptedAt: new Date() }).where(eq(invitations.id, id));
  }
}

class DrizzleAuditRepository implements AuditRepository {
  constructor(private readonly db: Db) {}
  async append(event: Parameters<AuditRepository['append']>[0]) {
    await this.db.insert(auditEvents).values({ ...event, ip: event.ip ?? null });
  }
  list(filter: { tenantId: string | null; beforeId?: number; limit: number }) {
    const conds = [filter.tenantId === null ? isNull(auditEvents.tenantId) : eq(auditEvents.tenantId, filter.tenantId)];
    if (filter.beforeId) conds.push(lt(auditEvents.id, filter.beforeId));
    return this.db
      .select({
        id: auditEvents.id,
        occurredAt: auditEvents.occurredAt,
        tenantId: auditEvents.tenantId,
        actor: auditEvents.actor,
        action: auditEvents.action,
        resource: auditEvents.resource,
        outcome: auditEvents.outcome,
        details: auditEvents.details,
        requestId: auditEvents.requestId,
      })
      .from(auditEvents)
      .where(and(...conds))
      .orderBy(desc(auditEvents.id))
      .limit(filter.limit);
  }
}

class SqlAuthzRepository implements AuthzRepository {
  constructor(private readonly db: Db) {}

  // Một truy vấn duy nhất lấy mọi dữ kiện cần cho quyết định phân quyền
  async facts(i: Parameters<AuthzRepository['facts']>[0]): Promise<AuthzFacts> {
    const result = await this.db.execute(sql`
      WITH principals AS (
        SELECT ${i.principalType}::text AS ptype, ${i.principalId}::text AS pid
        UNION ALL
        -- Người dùng thừa hưởng quyền của các nhóm họ thuộc về (chỉ trong tenant của resource)
        SELECT 'group', gm.group_id::text
          FROM iam.group_members gm
         WHERE ${i.principalType}::text = 'user'
           AND gm.tenant_id = ${i.tenantId}::uuid
           AND gm.user_id::text = ${i.principalId}::text
      )
      SELECT
        (p.name IS NOT NULL)                AS permission_exists,
        coalesce(p.requires_mfa, false)     AS requires_mfa,
        u.status                            AS user_status,
        coalesce(u.mfa_enrolled, false)     AS mfa_enrolled,
        t.status                            AS tenant_status,
        m.status                            AS membership_status,
        (SELECT rb.id::text
           FROM iam.role_bindings rb
           JOIN iam.role_permissions rp ON rp.role_id = rb.role_id AND rp.permission = ${i.permission}::text
           JOIN principals pr ON pr.ptype = rb.principal_type AND pr.pid = rb.principal_id
          WHERE (rb.resource = ${i.resource}::text OR starts_with(${i.resource}::text, rb.resource || '/'))
            AND (rb.expires_at IS NULL OR rb.expires_at > now())
          LIMIT 1)                          AS binding_id,
        (SELECT version FROM iam.policy_state WHERE id = 1) AS policy_version
      FROM (SELECT 1) AS one
      LEFT JOIN iam.permissions p ON p.name = ${i.permission}::text
      LEFT JOIN iam.users u ON ${i.principalType}::text = 'user' AND u.id::text = ${i.principalId}::text
      LEFT JOIN iam.tenants t ON t.id = ${i.tenantId}::uuid
      LEFT JOIN iam.memberships m
             ON ${i.principalType}::text = 'user' AND m.tenant_id = ${i.tenantId}::uuid AND m.user_id::text = ${i.principalId}::text
    `);
    const row = result.rows[0] as Record<string, unknown>;
    return {
      permissionExists: row.permission_exists === true,
      permissionRequiresMfa: row.requires_mfa === true,
      userStatus: (row.user_status as AuthzFacts['userStatus']) ?? null,
      mfaEnrolled: row.mfa_enrolled === true,
      tenantStatus: (row.tenant_status as AuthzFacts['tenantStatus']) ?? null,
      membershipStatus: (row.membership_status as AuthzFacts['membershipStatus']) ?? null,
      bindingId: (row.binding_id as string | null) ?? null,
      policyVersion: Number(row.policy_version ?? 0),
    };
  }

  async effectivePermissions(i: Parameters<AuthzRepository['effectivePermissions']>[0]) {
    const result = await this.db.execute(sql`
      WITH principals AS (
        SELECT ${i.principalType}::text AS ptype, ${i.principalId}::text AS pid
        UNION ALL
        SELECT 'group', gm.group_id::text FROM iam.group_members gm
         WHERE ${i.principalType}::text = 'user' AND gm.tenant_id = ${i.tenantId}::uuid AND gm.user_id::text = ${i.principalId}::text
      )
      SELECT DISTINCT rp.permission
        FROM iam.role_bindings rb
        JOIN iam.role_permissions rp ON rp.role_id = rb.role_id
        JOIN principals pr ON pr.ptype = rb.principal_type AND pr.pid = rb.principal_id
       WHERE (rb.resource = ${i.resource}::text OR starts_with(${i.resource}::text, rb.resource || '/'))
         AND (rb.expires_at IS NULL OR rb.expires_at > now())
       ORDER BY 1
    `);
    return result.rows.map((r) => (r as { permission: string }).permission);
  }
}

export function createRepositories(db: Db): Repositories {
  return {
    tenants: new DrizzleTenantRepository(db),
    users: new DrizzleUserRepository(db),
    memberships: new DrizzleMembershipRepository(db),
    groups: new DrizzleGroupRepository(db),
    roles: new DrizzleRoleRepository(db),
    bindings: new DrizzleBindingRepository(db),
    invitations: new DrizzleInvitationRepository(db),
    audit: new DrizzleAuditRepository(db),
    authz: new SqlAuthzRepository(db),
  };
}
