// Use case nhóm: tạo/xóa nhóm, thêm/bớt thành viên. Mọi thay đổi đều ghi audit.
import { NotFoundError } from '@ol/node-kit';
import { tenantResource } from '../domain/resource.js';
import type { Actor } from '../domain/types.js';
import { audit } from './audit.js';
import type { UnitOfWork } from './ports.js';

export class GroupService {
  private readonly uow: UnitOfWork;
  constructor(deps: { uow: UnitOfWork }) {
    this.uow = deps.uow;
  }

  list(tenantId: string) {
    return this.uow.repos.groups.list(tenantId);
  }

  async listMembers(tenantId: string, groupId: string) {
    if (!(await this.uow.repos.groups.get(tenantId, groupId))) throw new NotFoundError('Không tìm thấy nhóm');
    return this.uow.repos.groups.listMembers(tenantId, groupId);
  }

  create(actor: Actor, tenantId: string, input: { name: string; description?: string | null }) {
    return this.uow.run(async (r) => {
      const g = await r.groups.create({ tenantId, name: input.name, description: input.description ?? null });
      await audit(r, actor, { tenantId, action: 'iam.group.created', resource: `${tenantResource(tenantId)}/groups/${g.id}`, details: { name: g.name } });
      return g;
    });
  }

  delete(actor: Actor, tenantId: string, groupId: string) {
    return this.uow.run(async (r) => {
      if (!(await r.groups.delete(tenantId, groupId))) throw new NotFoundError('Không tìm thấy nhóm');
      await audit(r, actor, { tenantId, action: 'iam.group.deleted', resource: `${tenantResource(tenantId)}/groups/${groupId}` });
    });
  }

  addMember(actor: Actor, tenantId: string, groupId: string, userId: string) {
    return this.uow.run(async (r) => {
      if (!(await r.groups.get(tenantId, groupId))) throw new NotFoundError('Không tìm thấy nhóm');
      await r.groups.addMember(tenantId, groupId, userId);
      await audit(r, actor, { tenantId, action: 'iam.group.memberAdded', resource: `${tenantResource(tenantId)}/groups/${groupId}`, details: { userId } });
    });
  }

  removeMember(actor: Actor, tenantId: string, groupId: string, userId: string) {
    return this.uow.run(async (r) => {
      if (!(await r.groups.removeMember(tenantId, groupId, userId))) throw new NotFoundError('Người dùng không thuộc nhóm');
      await audit(r, actor, { tenantId, action: 'iam.group.memberRemoved', resource: `${tenantResource(tenantId)}/groups/${groupId}`, details: { userId } });
    });
  }
}
