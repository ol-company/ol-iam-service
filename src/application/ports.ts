// CỔNG (ports) của tầng application — interface mà use case phụ thuộc vào.
// Tầng infrastructure (Drizzle, Keycloak) hiện thực các interface này.
// Nhờ vậy use case không biết gì về SQL hay HTTP → thay thế/mock được khi test (Dependency Inversion).
import type {
  AuditEvent,
  Group,
  Invitation,
  Member,
  MembershipStatus,
  PrincipalType,
  Role,
  RoleBinding,
  Tenant,
  User,
  UserStatus,
} from '../domain/types.js';
import type { PermissionDef, RoleDef } from '../domain/catalog.js';

export interface TenantRepository {
  create(input: { slug: string; name: string }): Promise<Tenant>;
  findById(id: string): Promise<Tenant | null>;
  findBySlug(slug: string): Promise<Tenant | null>;
  list(): Promise<Tenant[]>;
}

export interface UserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  insert(input: { id: string; email: string; displayName: string | null; status: UserStatus }): Promise<User>;
  update(id: string, patch: Partial<Pick<User, 'email' | 'displayName' | 'status' | 'mfaEnrolled' | 'lastLoginAt'>>): Promise<void>;
}

export interface MembershipRepository {
  add(tenantId: string, userId: string): Promise<void>;
  remove(tenantId: string, userId: string): Promise<boolean>;
  get(tenantId: string, userId: string): Promise<{ status: MembershipStatus } | null>;
  setStatus(tenantId: string, userId: string, status: MembershipStatus): Promise<boolean>;
  listMembers(tenantId: string): Promise<Member[]>;
  listTenantsOfUser(userId: string): Promise<Array<Tenant & { membershipStatus: MembershipStatus }>>;
}

export interface GroupRepository {
  list(tenantId: string): Promise<Array<Group & { memberCount: number }>>;
  get(tenantId: string, groupId: string): Promise<Group | null>;
  create(input: { tenantId: string; name: string; description: string | null }): Promise<Group>;
  delete(tenantId: string, groupId: string): Promise<boolean>;
  listMembers(tenantId: string, groupId: string): Promise<User[]>;
  addMember(tenantId: string, groupId: string, userId: string): Promise<void>;
  removeMember(tenantId: string, groupId: string, userId: string): Promise<boolean>;
}

export interface RoleRepository {
  listAssignable(tenantId: string): Promise<Role[]>; // Role hệ thống loại tenant + role tùy chỉnh của tenant
  get(id: string): Promise<Role | null>;
  createCustom(input: { tenantId: string; id: string; title: string; description: string | null; permissions: string[] }): Promise<Role>;
  deleteCustom(tenantId: string, id: string): Promise<boolean>;
  countBindings(roleId: string): Promise<number>;
  syncCatalog(permissions: PermissionDef[], roles: RoleDef[]): Promise<void>;
  listPermissions(): Promise<PermissionDef[]>;
}

export interface BindingRepository {
  list(tenantId: string): Promise<RoleBinding[]>;
  get(tenantId: string | null, id: string): Promise<RoleBinding | null>;
  create(input: Omit<RoleBinding, 'id' | 'createdAt'>): Promise<RoleBinding>;
  ensure(input: Omit<RoleBinding, 'id' | 'createdAt' | 'expiresAt'>): Promise<void>; // Tạo nếu chưa có (idempotent)
  delete(tenantId: string | null, id: string): Promise<boolean>;
  deleteForPrincipal(tenantId: string, principalType: PrincipalType, principalId: string): Promise<number>;
  countForRole(roleId: string, resource: string): Promise<number>;
}

export interface InvitationRepository {
  create(input: { tenantId: string; email: string; roleIds: string[]; invitedBy: string; userId: string; expiresAt: Date }): Promise<Invitation>;
  list(tenantId: string): Promise<Invitation[]>;
  revoke(tenantId: string, id: string): Promise<Invitation | null>;
  findPendingByUser(userId: string): Promise<Invitation[]>;
  markAccepted(id: string): Promise<void>;
}

export interface AuditRepository {
  append(event: Omit<AuditEvent, 'id' | 'occurredAt'> & { ip?: string | null }): Promise<void>;
  list(filter: { tenantId: string | null; beforeId?: number; limit: number }): Promise<AuditEvent[]>;
}

// Dữ kiện thô để tầng application ra quyết định phân quyền
export interface AuthzFacts {
  permissionExists: boolean;
  permissionRequiresMfa: boolean;
  userStatus: UserStatus | null; // null nếu principal không phải user hoặc user chưa tồn tại
  mfaEnrolled: boolean;
  tenantStatus: 'active' | 'suspended' | null; // null nếu resource không thuộc tenant
  membershipStatus: MembershipStatus | null;
  bindingId: string | null;
  policyVersion: number;
}

export interface AuthzRepository {
  facts(input: { principalType: PrincipalType; principalId: string; permission: string; resource: string; tenantId: string | null }): Promise<AuthzFacts>;
  effectivePermissions(input: { principalType: PrincipalType; principalId: string; resource: string; tenantId: string | null }): Promise<string[]>;
}

export interface Repositories {
  tenants: TenantRepository;
  users: UserRepository;
  memberships: MembershipRepository;
  groups: GroupRepository;
  roles: RoleRepository;
  bindings: BindingRepository;
  invitations: InvitationRepository;
  audit: AuditRepository;
  authz: AuthzRepository;
}

// Unit of Work: gom nhiều thao tác ghi + audit vào MỘT transaction; lỗi thì rollback toàn bộ
export interface UnitOfWork {
  readonly repos: Repositories; // Đọc ngoài transaction
  run<T>(fn: (repos: Repositories) => Promise<T>): Promise<T>;
}

// Identity Provider (Keycloak) — IAM không lưu mật khẩu, mọi thao tác xác thực đi qua đây
export interface IdpUser {
  id: string;
  email: string;
  enabled: boolean;
  displayName: string | null;
}

export interface IdentityProvider {
  findUserByEmail(email: string): Promise<IdpUser | null>;
  getUser(id: string): Promise<IdpUser | null>;
  createUser(input: { email: string; displayName?: string; requiredActions: string[]; emailVerified?: boolean }): Promise<string>;
  sendActionsEmail(userId: string, actions: string[], lifespanSeconds: number): Promise<void>;
  setEnabled(userId: string, enabled: boolean): Promise<void>;
  logout(userId: string): Promise<void>;
  hasOtp(userId: string): Promise<boolean>;
  removeOtp(userId: string): Promise<void>;
  addRequiredActions(userId: string, actions: string[]): Promise<void>;
  setPassword(userId: string, password: string, temporary: boolean): Promise<void>; // Chỉ dùng cho seed local
}
