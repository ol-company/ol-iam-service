// Ánh xạ bảng PostgreSQL sang TypeScript cho Drizzle (chỉ dùng để truy vấn có kiểu).
// Cấu trúc bảng thật được định nghĩa bằng SQL trong migrations/ — hai nơi phải khớp nhau;
// test integration chạy migration thật rồi truy vấn qua schema này nên sẽ phát hiện lệch.
import {
  bigint,
  boolean,
  integer,
  jsonb,
  pgSchema,
  primaryKey,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';

export const iam = pgSchema('iam');

export const tenants = iam.table('tenants', {
  id: uuid('id').primaryKey().defaultRandom(),
  slug: text('slug').notNull(),
  name: text('name').notNull(),
  status: text('status', { enum: ['active', 'suspended'] })
    .notNull()
    .default('active'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const users = iam.table('users', {
  id: uuid('id').primaryKey(),
  email: text('email').notNull(),
  displayName: text('display_name'),
  status: text('status', { enum: ['invited', 'active', 'disabled'] })
    .notNull()
    .default('invited'),
  mfaEnrolled: boolean('mfa_enrolled').notNull().default(false),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
});

export const memberships = iam.table(
  'memberships',
  {
    tenantId: uuid('tenant_id').notNull(),
    userId: uuid('user_id').notNull(),
    status: text('status', { enum: ['active', 'disabled'] })
      .notNull()
      .default('active'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.tenantId, t.userId] })],
);

export const groups = iam.table('groups', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull(),
  name: text('name').notNull(),
  description: text('description'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const groupMembers = iam.table(
  'group_members',
  {
    tenantId: uuid('tenant_id').notNull(),
    groupId: uuid('group_id').notNull(),
    userId: uuid('user_id').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.groupId, t.userId] })],
);

export const permissions = iam.table('permissions', {
  name: text('name').primaryKey(),
  description: text('description').notNull(),
  requiresMfa: boolean('requires_mfa').notNull().default(false),
  assignable: text('assignable', { enum: ['tenant', 'platform', 'service'] }).notNull(),
});

export const roles = iam.table('roles', {
  id: text('id').primaryKey(),
  tenantId: uuid('tenant_id'),
  title: text('title').notNull(),
  description: text('description'),
  isSystem: boolean('is_system').notNull().default(false),
  assignable: text('assignable', { enum: ['tenant', 'platform', 'service'] }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const rolePermissions = iam.table(
  'role_permissions',
  {
    roleId: text('role_id').notNull(),
    permission: text('permission').notNull(),
  },
  (t) => [primaryKey({ columns: [t.roleId, t.permission] })],
);

export const roleBindings = iam.table('role_bindings', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id'),
  principalType: text('principal_type', { enum: ['user', 'group', 'service'] }).notNull(),
  principalId: text('principal_id').notNull(),
  roleId: text('role_id').notNull(),
  resource: text('resource').notNull(),
  createdBy: text('created_by').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp('expires_at', { withTimezone: true }),
});

export const invitations = iam.table('invitations', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull(),
  email: text('email').notNull(),
  roleIds: text('role_ids').array().notNull(),
  status: text('status', { enum: ['pending', 'accepted', 'revoked', 'expired'] })
    .notNull()
    .default('pending'),
  invitedBy: text('invited_by').notNull(),
  userId: uuid('user_id'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  acceptedAt: timestamp('accepted_at', { withTimezone: true }),
});

export const auditEvents = iam.table('audit_events', {
  id: bigint('id', { mode: 'number' }).primaryKey().generatedAlwaysAsIdentity(),
  occurredAt: timestamp('occurred_at', { withTimezone: true }).notNull().defaultNow(),
  tenantId: uuid('tenant_id'),
  actor: text('actor').notNull(),
  action: text('action').notNull(),
  resource: text('resource').notNull(),
  outcome: text('outcome', { enum: ['success', 'denied', 'error'] }).notNull(),
  details: jsonb('details').$type<Record<string, unknown>>().notNull().default({}),
  requestId: text('request_id'),
  ip: text('ip'),
});

export const policyState = iam.table('policy_state', {
  id: integer('id').primaryKey(),
  version: bigint('version', { mode: 'number' }).notNull(),
});

export const schema = {
  tenants,
  users,
  memberships,
  groups,
  groupMembers,
  permissions,
  roles,
  rolePermissions,
  roleBindings,
  invitations,
  auditEvents,
  policyState,
};
