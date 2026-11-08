// Test đơn vị cho quy tắc phân quyền thuần (không cần DB)
import { describe, expect, it } from 'vitest';
import { decide } from '../src/application/authz-service.js';
import type { AuthzFacts } from '../src/application/ports.js';
import { isWithin, parsePrincipal, tenantOf } from '../src/domain/resource.js';

const ok: AuthzFacts = {
  permissionExists: true,
  permissionRequiresMfa: false,
  userStatus: 'active',
  mfaEnrolled: false,
  tenantStatus: 'active',
  membershipStatus: 'active',
  bindingId: 'b1',
  policyVersion: 1,
};

describe('decide()', () => {
  it('cho phép khi đủ điều kiện', () =>
    expect(decide(ok, 'user', true)).toEqual({ allow: true, reason: 'binding' }));
  it('mặc định từ chối khi không có binding', () =>
    expect(decide({ ...ok, bindingId: null }, 'user', true).reason).toBe('no-binding'));
  it('từ chối permission không tồn tại', () =>
    expect(decide({ ...ok, permissionExists: false }, 'user', true).reason).toBe(
      'unknown-permission',
    ));
  it('từ chối người dùng bị khóa', () =>
    expect(decide({ ...ok, userStatus: 'disabled' }, 'user', true).reason).toBe(
      'principal-disabled',
    ));
  it('từ chối người ngoài tenant dù có binding', () =>
    expect(decide({ ...ok, membershipStatus: null }, 'user', true).reason).toBe('not-member'));
  it('từ chối thành viên bị vô hiệu hóa', () =>
    expect(decide({ ...ok, membershipStatus: 'disabled' }, 'user', true).reason).toBe(
      'membership-disabled',
    ));
  it('yêu cầu MFA cho thao tác quản trị', () =>
    expect(decide({ ...ok, permissionRequiresMfa: true }, 'user', true).reason).toBe(
      'mfa-required',
    ));
  it('cho phép thao tác quản trị khi đã có MFA', () =>
    expect(
      decide({ ...ok, permissionRequiresMfa: true, mfaEnrolled: true }, 'user', true).allow,
    ).toBe(true));
  it('từ chối tenant bị đình chỉ', () =>
    expect(decide({ ...ok, tenantStatus: 'suspended' }, 'user', true).reason).toBe(
      'tenant-suspended',
    ));
  it('service không cần membership', () =>
    expect(
      decide({ ...ok, userStatus: null, membershipStatus: null }, 'service', false).allow,
    ).toBe(true));
});

describe('resource', () => {
  it('kế thừa từ cha xuống con', () => {
    expect(isWithin('tenants/a/warehouses/w1', 'tenants/a')).toBe(true);
    expect(isWithin('tenants/a', 'tenants/a')).toBe(true);
    expect(isWithin('tenants/ab/warehouses/w1', 'tenants/a')).toBe(false); // không nhầm tiền tố "a" với "ab"
  });
  it('tách tenant và principal', () => {
    expect(tenantOf('tenants/t1/warehouses/w1')).toBe('t1');
    expect(tenantOf('platform')).toBeNull();
    expect(parsePrincipal('services/ol-bff')).toEqual({ type: 'service', id: 'ol-bff' });
  });
});
