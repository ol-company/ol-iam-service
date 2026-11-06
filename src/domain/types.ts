// Thực thể miền IAM (kiểu dữ liệu thuần, không phụ thuộc framework)

export type TenantStatus = 'active' | 'suspended';
export type UserStatus = 'invited' | 'active' | 'disabled';
export type MembershipStatus = 'active' | 'disabled';
export type PrincipalType = 'user' | 'group' | 'service';

export interface Tenant {
  id: string;
  slug: string;
  name: string;
  status: TenantStatus;
  createdAt: Date;
}

export interface User {
  id: string;
  email: string;
  displayName: string | null;
  status: UserStatus;
  mfaEnrolled: boolean;
  createdAt: Date;
  lastLoginAt: Date | null;
}

export interface Member extends User {
  membershipStatus: MembershipStatus;
}

export interface Group {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  createdAt: Date;
}

export interface Role {
  id: string;
  tenantId: string | null;
  title: string;
  description: string | null;
  isSystem: boolean;
  assignable: 'platform' | 'tenant' | 'service';
  permissions: string[];
}

export interface RoleBinding {
  id: string;
  tenantId: string | null;
  principalType: PrincipalType;
  principalId: string;
  roleId: string;
  resource: string;
  createdBy: string;
  createdAt: Date;
  expiresAt: Date | null;
}

export interface Invitation {
  id: string;
  tenantId: string;
  email: string;
  roleIds: string[];
  status: 'pending' | 'accepted' | 'revoked' | 'expired';
  invitedBy: string;
  userId: string | null;
  createdAt: Date;
  expiresAt: Date;
}

export interface AuditEvent {
  id: number;
  occurredAt: Date;
  tenantId: string | null;
  actor: string;
  action: string;
  resource: string;
  outcome: 'success' | 'denied' | 'error';
  details: Record<string, unknown>;
  requestId: string | null;
}

// Ai đang thực hiện thao tác (lấy từ token đã xác minh)
export interface Actor {
  id: string; // "users/<sub>" hoặc "services/<clientId>"
  requestId?: string;
  ip?: string;
}
