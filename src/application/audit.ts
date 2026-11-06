// Ghi audit trong CÙNG transaction với thao tác → thao tác thành công thì chắc chắn có bản ghi audit.
import type { Actor } from '../domain/types.js';
import type { Repositories } from './ports.js';

export interface AuditInput {
  tenantId: string | null;
  action: string; // Ví dụ: iam.user.invited
  resource: string; // Tài nguyên bị tác động
  outcome?: 'success' | 'denied' | 'error';
  details?: Record<string, unknown>; // KHÔNG đưa mật khẩu/token vào đây
}

export function audit(repos: Repositories, actor: Actor, input: AuditInput): Promise<void> {
  return repos.audit.append({
    tenantId: input.tenantId,
    actor: actor.id,
    action: input.action,
    resource: input.resource,
    outcome: input.outcome ?? 'success',
    details: input.details ?? {},
    requestId: actor.requestId ?? null,
    ip: actor.ip ?? null,
  });
}
