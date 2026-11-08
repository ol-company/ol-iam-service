// Quy tắc về tên tài nguyên — hàm thuần, không phụ thuộc DB hay HTTP → test đơn vị dễ.
import { RESOURCE_PATTERN } from '@ol/node-kit';

export const PLATFORM = 'platform';

export function tenantResource(tenantId: string): string {
  return `tenants/${tenantId}`;
}

// Lấy tenantId từ tên tài nguyên; null nếu là "platform"
export function tenantOf(resource: string): string | null {
  const m = /^tenants\/([^/]+)/.exec(resource);
  return m?.[1] ?? null;
}

// resource có nằm trong phạm vi scope không (kế thừa từ cha xuống con)
export function isWithin(resource: string, scope: string): boolean {
  return resource === scope || resource.startsWith(`${scope}/`);
}

export function isValidResource(resource: string): boolean {
  return RESOURCE_PATTERN.test(resource);
}

// Tách "users/<id>" → { type: 'user', id }
export function parsePrincipal(principal: string): {
  type: 'user' | 'group' | 'service';
  id: string;
} {
  const [kind, id] = principal.split('/');
  if (!id) throw new Error(`Principal không hợp lệ: ${principal}`);
  const map = { users: 'user', groups: 'group', services: 'service' } as const;
  const type = map[kind as keyof typeof map];
  if (!type) throw new Error(`Principal không hợp lệ: ${principal}`);
  return { type, id };
}
