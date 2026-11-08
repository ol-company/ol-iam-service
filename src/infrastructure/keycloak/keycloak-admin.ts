// Hiện thực IdentityProvider bằng Keycloak Admin REST API.
// IAM xác thực với Keycloak bằng service account của client "ol-iam-service"
// (được cấp role realm-management: manage-users, view-users, query-users trong cấu hình realm).
// Tài liệu API: https://www.keycloak.org/docs-api/latest/rest-api/
import { ConflictError, DependencyUnavailableError, type TokenProvider } from '@ol/node-kit';
import type { IdentityProvider, IdpUser } from '../../application/ports.js';

export interface KeycloakAdminOptions {
  baseUrl: string; // URL nội bộ, ví dụ http://keycloak:8080
  realm: string; // ol
  tokenProvider: TokenProvider;
  clientId: string; // Client mà link trong email quay về (ol-bff)
  redirectUri: string; // Trang quay về sau khi hoàn tất hành động trong email (APP_URL + "/")
  timeoutMs?: number;
}

interface KcUser {
  id: string;
  email?: string;
  enabled: boolean;
  firstName?: string;
  lastName?: string;
  requiredActions?: string[];
}

export class KeycloakAdminClient implements IdentityProvider {
  constructor(private readonly o: KeycloakAdminOptions) {}

  private url(path: string): string {
    return `${this.o.baseUrl}/admin/realms/${encodeURIComponent(this.o.realm)}${path}`;
  }

  private async call(method: string, path: string, body?: unknown): Promise<Response> {
    const token = await this.o.tokenProvider.getToken();
    let res: Response;
    try {
      res = await fetch(this.url(path), {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.o.timeoutMs ?? 5_000),
      });
    } catch {
      throw new DependencyUnavailableError('keycloak-admin');
    }
    if (res.status === 409)
      throw new ConflictError('Người dùng đã tồn tại trong Identity Provider');
    if (res.status >= 500)
      throw new DependencyUnavailableError(`keycloak-admin (HTTP ${res.status})`);
    return res;
  }

  private async expectOk(res: Response, action: string): Promise<void> {
    if (!res.ok)
      throw new Error(`Keycloak ${action} thất bại: HTTP ${res.status} ${await res.text()}`);
  }

  private toIdpUser(u: KcUser): IdpUser {
    const name = [u.firstName, u.lastName].filter(Boolean).join(' ').trim();
    return {
      id: u.id,
      email: (u.email ?? '').toLowerCase(),
      enabled: u.enabled,
      displayName: name || null,
    };
  }

  async findUserByEmail(email: string): Promise<IdpUser | null> {
    const res = await this.call('GET', `/users?email=${encodeURIComponent(email)}&exact=true`);
    await this.expectOk(res, 'tìm user');
    const list = (await res.json()) as KcUser[];
    return list[0] ? this.toIdpUser(list[0]) : null;
  }

  async getUser(id: string): Promise<IdpUser | null> {
    const res = await this.call('GET', `/users/${encodeURIComponent(id)}`);
    if (res.status === 404) return null;
    await this.expectOk(res, 'đọc user');
    return this.toIdpUser((await res.json()) as KcUser);
  }

  async createUser(input: {
    email: string;
    displayName?: string;
    requiredActions: string[];
    emailVerified?: boolean;
  }): Promise<string> {
    const res = await this.call('POST', '/users', {
      username: input.email, // Đăng nhập bằng email
      email: input.email,
      firstName: input.displayName,
      enabled: true,
      emailVerified: input.emailVerified ?? false, // Chỉ seed local mới đặt true
      requiredActions: input.requiredActions, // Ví dụ UPDATE_PASSWORD, VERIFY_EMAIL, CONFIGURE_TOTP
    });
    await this.expectOk(res, 'tạo user');
    // Keycloak trả id trong header Location: .../users/<id>
    const location = res.headers.get('location') ?? '';
    const id = location.substring(location.lastIndexOf('/') + 1);
    if (!id) throw new Error('Keycloak không trả về id user');
    return id;
  }

  async sendActionsEmail(
    userId: string,
    actions: string[],
    lifespanSeconds: number,
  ): Promise<void> {
    const qs = new URLSearchParams({
      lifespan: String(lifespanSeconds),
      client_id: this.o.clientId,
      redirect_uri: this.o.redirectUri,
    });
    const res = await this.call(
      'PUT',
      `/users/${encodeURIComponent(userId)}/execute-actions-email?${qs}`,
      actions,
    );
    await this.expectOk(res, 'gửi email hành động');
  }

  async setEnabled(userId: string, enabled: boolean): Promise<void> {
    const res = await this.call('PUT', `/users/${encodeURIComponent(userId)}`, { enabled });
    await this.expectOk(res, 'bật/tắt user');
  }

  async logout(userId: string): Promise<void> {
    // Hủy mọi phiên SSO → Keycloak gửi back-channel logout tới BFF
    const res = await this.call('POST', `/users/${encodeURIComponent(userId)}/logout`);
    await this.expectOk(res, 'đăng xuất user');
  }

  async hasOtp(userId: string): Promise<boolean> {
    const res = await this.call('GET', `/users/${encodeURIComponent(userId)}/credentials`);
    await this.expectOk(res, 'đọc credentials');
    const creds = (await res.json()) as Array<{ type: string }>;
    return creds.some((c) => c.type === 'otp' || c.type === 'webauthn');
  }

  async removeOtp(userId: string): Promise<void> {
    const res = await this.call('GET', `/users/${encodeURIComponent(userId)}/credentials`);
    await this.expectOk(res, 'đọc credentials');
    const creds = (await res.json()) as Array<{ id: string; type: string }>;
    for (const c of creds.filter((x) => x.type === 'otp' || x.type === 'webauthn')) {
      const del = await this.call(
        'DELETE',
        `/users/${encodeURIComponent(userId)}/credentials/${encodeURIComponent(c.id)}`,
      );
      await this.expectOk(del, 'xóa credential');
    }
  }

  async addRequiredActions(userId: string, actions: string[]): Promise<void> {
    const res = await this.call('GET', `/users/${encodeURIComponent(userId)}`);
    await this.expectOk(res, 'đọc user');
    const user = (await res.json()) as KcUser;
    const merged = Array.from(new Set([...(user.requiredActions ?? []), ...actions]));
    const upd = await this.call('PUT', `/users/${encodeURIComponent(userId)}`, {
      requiredActions: merged,
    });
    await this.expectOk(upd, 'cập nhật required actions');
  }

  async setPassword(userId: string, password: string, temporary: boolean): Promise<void> {
    const res = await this.call('PUT', `/users/${encodeURIComponent(userId)}/reset-password`, {
      type: 'password',
      value: password,
      temporary,
    });
    await this.expectOk(res, 'đặt mật khẩu');
  }
}
