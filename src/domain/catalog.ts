// DANH MỤC PERMISSION VÀ ROLE HỆ THỐNG — nguồn sự thật duy nhất, đồng bộ vào DB khi chạy migrate.
// Thêm service mới = thêm permission + role của service đó vào đây qua Pull Request (security review).
//
// Quy ước tên permission: <service>.<resource>.<verb>  (học từ Google Cloud IAM)
// assignable:
//   - platform : chỉ gán được ở phạm vi "platform" (đội vận hành)
//   - tenant   : gán được trong tenant
//   - service  : chỉ gán cho danh tính service
// requiresMfa: thao tác quản trị — người dùng phải đã đăng ký MFA mới được phép

export interface PermissionDef {
  name: string;
  description: string;
  assignable: 'platform' | 'tenant' | 'service';
  requiresMfa?: boolean;
}

export interface RoleDef {
  id: string;
  title: string;
  description: string;
  assignable: 'platform' | 'tenant' | 'service';
  permissions: string[];
}

export const PERMISSIONS: PermissionDef[] = [
  // --- Platform (đội vận hành) ---
  {
    name: 'platform.tenants.create',
    description: 'Tạo tenant mới',
    assignable: 'platform',
    requiresMfa: true,
  },
  {
    name: 'platform.tenants.list',
    description: 'Liệt kê mọi tenant',
    assignable: 'platform',
    requiresMfa: true,
  },
  {
    name: 'platform.users.disable',
    description: 'Khóa/mở khóa người dùng trên toàn platform',
    assignable: 'platform',
    requiresMfa: true,
  },
  {
    name: 'platform.users.logout',
    description: 'Đăng xuất mọi phiên của người dùng',
    assignable: 'platform',
    requiresMfa: true,
  },
  {
    name: 'platform.users.resetMfa',
    description: 'Đặt lại MFA của người dùng',
    assignable: 'platform',
    requiresMfa: true,
  },
  {
    name: 'platform.audit.list',
    description: 'Xem audit log cấp platform',
    assignable: 'platform',
    requiresMfa: true,
  },

  // --- IAM trong tenant ---
  { name: 'iam.tenants.get', description: 'Xem thông tin tenant', assignable: 'tenant' },
  { name: 'iam.users.list', description: 'Xem người dùng và lời mời', assignable: 'tenant' },
  {
    name: 'iam.users.invite',
    description: 'Mời hoặc thu hồi lời mời',
    assignable: 'tenant',
    requiresMfa: true,
  },
  {
    name: 'iam.users.disable',
    description: 'Vô hiệu hóa thành viên trong tenant',
    assignable: 'tenant',
    requiresMfa: true,
  },
  {
    name: 'iam.users.enable',
    description: 'Kích hoạt lại thành viên',
    assignable: 'tenant',
    requiresMfa: true,
  },
  {
    name: 'iam.users.resetPassword',
    description: 'Gửi email đặt lại mật khẩu',
    assignable: 'tenant',
    requiresMfa: true,
  },
  { name: 'iam.groups.list', description: 'Xem nhóm', assignable: 'tenant' },
  { name: 'iam.groups.create', description: 'Tạo nhóm', assignable: 'tenant', requiresMfa: true },
  { name: 'iam.groups.delete', description: 'Xóa nhóm', assignable: 'tenant', requiresMfa: true },
  {
    name: 'iam.groups.manageMembers',
    description: 'Thêm/bớt thành viên nhóm',
    assignable: 'tenant',
    requiresMfa: true,
  },
  { name: 'iam.roles.list', description: 'Xem role', assignable: 'tenant' },
  {
    name: 'iam.roles.create',
    description: 'Tạo role tùy chỉnh',
    assignable: 'tenant',
    requiresMfa: true,
  },
  {
    name: 'iam.roles.delete',
    description: 'Xóa role tùy chỉnh',
    assignable: 'tenant',
    requiresMfa: true,
  },
  { name: 'iam.roleBindings.list', description: 'Xem gán quyền', assignable: 'tenant' },
  {
    name: 'iam.roleBindings.create',
    description: 'Gán quyền',
    assignable: 'tenant',
    requiresMfa: true,
  },
  {
    name: 'iam.roleBindings.delete',
    description: 'Thu hồi quyền',
    assignable: 'tenant',
    requiresMfa: true,
  },
  { name: 'iam.audit.list', description: 'Xem audit log của tenant', assignable: 'tenant' },

  // --- Dành cho service ---
  { name: 'iam.authz.check', description: 'Gọi API authorize', assignable: 'service' },

  // --- Warehouse ---
  { name: 'warehouse.warehouses.list', description: 'Liệt kê kho', assignable: 'tenant' },
  { name: 'warehouse.warehouses.get', description: 'Xem kho', assignable: 'tenant' },
  { name: 'warehouse.warehouses.create', description: 'Tạo kho', assignable: 'tenant' },
  { name: 'warehouse.items.list', description: 'Liệt kê mặt hàng trong kho', assignable: 'tenant' },
  {
    name: 'warehouse.items.get',
    description: 'Xem mặt hàng và lịch sử nhập/xuất',
    assignable: 'tenant',
  },
  { name: 'warehouse.items.create', description: 'Tạo mặt hàng', assignable: 'tenant' },
  { name: 'warehouse.stock.adjust', description: 'Điều chỉnh tồn kho', assignable: 'tenant' },
];

const iamRead = [
  'iam.tenants.get',
  'iam.users.list',
  'iam.groups.list',
  'iam.roles.list',
  'iam.roleBindings.list',
];
const whRead = [
  'warehouse.warehouses.list',
  'warehouse.warehouses.get',
  'warehouse.items.list',
  'warehouse.items.get',
];

export const SYSTEM_ROLES: RoleDef[] = [
  {
    id: 'roles/platform.admin',
    title: 'Platform Admin',
    description:
      'Quản lý tenant và người dùng toàn platform. KHÔNG có quyền đọc dữ liệu nghiệp vụ của tenant.',
    assignable: 'platform',
    permissions: PERMISSIONS.filter((p) => p.assignable === 'platform').map((p) => p.name),
  },
  {
    id: 'roles/iam.tenantAdmin',
    title: 'Tenant Admin',
    description: 'Quản trị người dùng, nhóm, role và gán quyền trong tenant',
    assignable: 'tenant',
    permissions: PERMISSIONS.filter(
      (p) => p.assignable === 'tenant' && p.name.startsWith('iam.'),
    ).map((p) => p.name),
  },
  {
    id: 'roles/iam.viewer',
    title: 'IAM Viewer',
    description: 'Chỉ xem cấu hình IAM của tenant',
    assignable: 'tenant',
    permissions: iamRead,
  },
  {
    id: 'roles/iam.auditor',
    title: 'Auditor',
    description: 'Xem cấu hình IAM và audit log',
    assignable: 'tenant',
    permissions: [...iamRead, 'iam.audit.list'],
  },
  {
    id: 'roles/warehouse.viewer',
    title: 'Warehouse Viewer',
    description: 'Xem kho và tồn kho',
    assignable: 'tenant',
    permissions: ['iam.tenants.get', ...whRead],
  },
  {
    id: 'roles/warehouse.operator',
    title: 'Warehouse Operator',
    description: 'Tạo mặt hàng và điều chỉnh tồn kho',
    assignable: 'tenant',
    permissions: ['iam.tenants.get', ...whRead, 'warehouse.items.create', 'warehouse.stock.adjust'],
  },
  {
    id: 'roles/warehouse.manager',
    title: 'Warehouse Manager',
    description: 'Toàn quyền nghiệp vụ kho trong phạm vi được gán',
    assignable: 'tenant',
    permissions: [
      'iam.tenants.get',
      ...whRead,
      'warehouse.warehouses.create',
      'warehouse.items.create',
      'warehouse.stock.adjust',
    ],
  },
  {
    id: 'roles/iam.authzChecker',
    title: 'Authorization Checker',
    description: 'Cho service gọi API authorize',
    assignable: 'service',
    permissions: ['iam.authz.check'],
  },
];

// Service được phép gọi authorize (client id trong Keycloak). Đồng bộ binding khi migrate.
export const AUTHZ_CHECKER_SERVICES = ['ol-warehouse-service'];

export const PERMISSION_BY_NAME = new Map(PERMISSIONS.map((p) => [p.name, p]));

export function requiresMfa(permissions: string[]): boolean {
  return permissions.some((p) => PERMISSION_BY_NAME.get(p)?.requiresMfa === true);
}
