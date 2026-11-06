-- =============================================================================
-- 0000_init — Lược đồ IAM ban đầu
-- Chạy bởi role iam_migrator (chủ sở hữu schema iam). Role iam_app (ứng dụng) nhận quyền
-- SELECT/INSERT/UPDATE/DELETE qua "ALTER DEFAULT PRIVILEGES" trong script bootstrap DB
-- (ol-infra/db/bootstrap.sql). File này KHÔNG được sửa sau khi đã chạy ở bất kỳ môi trường nào;
-- thay đổi tiếp theo phải là migration mới (pnpm db:new <tên>).
-- =============================================================================

-- Tenant (tổ chức khách hàng)
CREATE TABLE iam.tenants (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$'),
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Người dùng. id = "sub" của Keycloak → một nguồn danh tính duy nhất
CREATE TABLE iam.users (
  id             uuid PRIMARY KEY,
  email          text NOT NULL UNIQUE CHECK (email = lower(email) AND position('@' IN email) > 1),
  display_name   text,
  status         text NOT NULL DEFAULT 'invited' CHECK (status IN ('invited', 'active', 'disabled')),
  mfa_enrolled   boolean NOT NULL DEFAULT false,
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_login_at  timestamptz
);

-- Thành viên của tenant
CREATE TABLE iam.memberships (
  tenant_id   uuid NOT NULL REFERENCES iam.tenants(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX memberships_user_idx ON iam.memberships (user_id);

-- Nhóm trong tenant
CREATE TABLE iam.groups (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES iam.tenants(id) ON DELETE CASCADE,
  name         text NOT NULL CHECK (name ~ '^[A-Za-z0-9 ._-]{2,64}$'),
  description  text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id) -- Cho phép khóa ngoại kép (tenant_id, group_id) → không thể ghép nhóm khác tenant
);

-- Thành viên nhóm: khóa ngoại kép bảo đảm user và group cùng tenant, và user phải là thành viên tenant
CREATE TABLE iam.group_members (
  tenant_id   uuid NOT NULL,
  group_id    uuid NOT NULL,
  user_id     uuid NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, user_id),
  FOREIGN KEY (tenant_id, group_id) REFERENCES iam.groups (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES iam.memberships (tenant_id, user_id) ON DELETE CASCADE
);
CREATE INDEX group_members_user_idx ON iam.group_members (tenant_id, user_id);

-- Danh mục permission (đồng bộ từ code: src/domain/catalog.ts)
CREATE TABLE iam.permissions (
  name          text PRIMARY KEY CHECK (name ~ '^[a-z]+\.[a-zA-Z]+\.[a-zA-Z]+$'),
  description   text NOT NULL,
  requires_mfa  boolean NOT NULL DEFAULT false,
  assignable    text NOT NULL CHECK (assignable IN ('tenant', 'platform', 'service'))
);

-- Role: hệ thống (tenant_id NULL, id "roles/...") hoặc tùy chỉnh của tenant (id "tenants/<id>/roles/<tên>")
CREATE TABLE iam.roles (
  id           text PRIMARY KEY,
  tenant_id    uuid REFERENCES iam.tenants(id) ON DELETE CASCADE,
  title        text NOT NULL,
  description  text,
  is_system    boolean NOT NULL DEFAULT false,
  assignable   text NOT NULL CHECK (assignable IN ('tenant', 'platform', 'service')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (is_system AND tenant_id IS NULL AND id LIKE 'roles/%')
    OR (NOT is_system AND tenant_id IS NOT NULL AND id = 'tenants/' || tenant_id::text || '/roles/' || split_part(id, '/', 4))
  )
);

CREATE TABLE iam.role_permissions (
  role_id     text NOT NULL REFERENCES iam.roles(id) ON DELETE CASCADE,
  permission  text NOT NULL REFERENCES iam.permissions(name) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission)
);

-- Gán quyền = principal + role + phạm vi (resource). Kế thừa: binding ở "tenants/A"
-- có hiệu lực cho mọi resource bắt đầu bằng "tenants/A/".
CREATE TABLE iam.role_bindings (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid REFERENCES iam.tenants(id) ON DELETE CASCADE,
  principal_type  text NOT NULL CHECK (principal_type IN ('user', 'group', 'service')),
  principal_id    text NOT NULL CHECK (principal_id ~ '^[A-Za-z0-9._-]{1,128}$'),
  role_id         text NOT NULL REFERENCES iam.roles(id), -- Không CASCADE: không xóa được role đang được gán
  resource        text NOT NULL CHECK (resource ~ '^(platform|tenants/[0-9a-f-]{36}(/[A-Za-z0-9._-]{1,128})*)$'),
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz, -- Dùng cho quyền tạm thời (break-glass)
  UNIQUE (principal_type, principal_id, role_id, resource),
  -- Binding của tenant phải nằm trong cây tài nguyên của chính tenant đó
  CHECK (
    (tenant_id IS NULL AND resource = 'platform')
    OR (tenant_id IS NOT NULL AND (resource = 'tenants/' || tenant_id::text
        OR starts_with(resource, 'tenants/' || tenant_id::text || '/')))
  )
);
CREATE INDEX role_bindings_principal_idx ON iam.role_bindings (principal_type, principal_id);
CREATE INDEX role_bindings_tenant_idx ON iam.role_bindings (tenant_id);

-- Lời mời người dùng vào tenant
CREATE TABLE iam.invitations (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES iam.tenants(id) ON DELETE CASCADE,
  email        text NOT NULL CHECK (email = lower(email)),
  role_ids     text[] NOT NULL,
  status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
  invited_by   text NOT NULL,
  user_id      uuid REFERENCES iam.users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  accepted_at  timestamptz
);
CREATE UNIQUE INDEX invitations_pending_uq ON iam.invitations (tenant_id, email) WHERE status = 'pending';

-- Nhật ký kiểm toán: chỉ thêm, không sửa/xóa (quyền UPDATE/DELETE bị thu hồi bên dưới)
CREATE TABLE iam.audit_events (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  tenant_id    uuid,
  actor        text NOT NULL,
  action       text NOT NULL,
  resource     text NOT NULL,
  outcome      text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
  details      jsonb NOT NULL DEFAULT '{}'::jsonb,
  request_id   text,
  ip           text
);
CREATE INDEX audit_events_tenant_idx ON iam.audit_events (tenant_id, id DESC);
CREATE INDEX audit_events_time_idx ON iam.audit_events (occurred_at);

-- Phiên bản chính sách: tăng mỗi khi dữ liệu ảnh hưởng tới phân quyền thay đổi
CREATE TABLE iam.policy_state (
  id       int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version  bigint NOT NULL DEFAULT 0
);
INSERT INTO iam.policy_state (id, version) VALUES (1, 0);

CREATE FUNCTION iam.bump_policy_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE iam.policy_state SET version = version + 1 WHERE id = 1;
  RETURN NULL;
END;
$$;

CREATE TRIGGER bump_on_bindings AFTER INSERT OR UPDATE OR DELETE ON iam.role_bindings
  FOR EACH STATEMENT EXECUTE FUNCTION iam.bump_policy_version();
CREATE TRIGGER bump_on_role_permissions AFTER INSERT OR UPDATE OR DELETE ON iam.role_permissions
  FOR EACH STATEMENT EXECUTE FUNCTION iam.bump_policy_version();
CREATE TRIGGER bump_on_group_members AFTER INSERT OR UPDATE OR DELETE ON iam.group_members
  FOR EACH STATEMENT EXECUTE FUNCTION iam.bump_policy_version();
CREATE TRIGGER bump_on_memberships AFTER INSERT OR UPDATE OR DELETE ON iam.memberships
  FOR EACH STATEMENT EXECUTE FUNCTION iam.bump_policy_version();
CREATE TRIGGER bump_on_users AFTER UPDATE OF status, mfa_enrolled ON iam.users
  FOR EACH STATEMENT EXECUTE FUNCTION iam.bump_policy_version();
CREATE TRIGGER bump_on_tenants AFTER UPDATE OF status ON iam.tenants
  FOR EACH STATEMENT EXECUTE FUNCTION iam.bump_policy_version();

-- Audit chỉ được thêm: thu hồi quyền sửa/xóa của role ứng dụng
REVOKE UPDATE, DELETE, TRUNCATE ON iam.audit_events FROM iam_app;
