// Bản giả (fake) cho phụ thuộc bên ngoài để test không cần Keycloak thật.
import { randomUUID } from 'node:crypto';
import { UnauthenticatedError, type Principal, type TokenVerifier } from '@ol/node-kit';
import type { IdentityProvider, IdpUser } from '../../src/application/ports.js';

// Token giả: "user:<uuid>:<email>" hoặc "service:<clientId>"
export class FakeVerifier implements TokenVerifier {
  async verify(token: string): Promise<Principal> {
    const [kind, id, email] = token.split(':');
    if (kind === 'user' && id) return { type: 'user', id: `users/${id}`, subject: id, email, token, claims: {} };
    if (kind === 'service' && id) return { type: 'service', id: `services/${id}`, subject: id, token, claims: {} };
    throw new UnauthenticatedError();
  }
}

export class FakeIdp implements IdentityProvider {
  users = new Map<string, IdpUser & { requiredActions: string[]; otp: boolean }>();
  emails: Array<{ userId: string; actions: string[] }> = [];
  loggedOut: string[] = [];

  async findUserByEmail(email: string) {
    return [...this.users.values()].find((u) => u.email === email) ?? null;
  }
  async getUser(id: string) {
    return this.users.get(id) ?? null;
  }
  async createUser(input: { email: string; requiredActions: string[] }) {
    const id = randomUUID();
    this.users.set(id, { id, email: input.email, enabled: true, displayName: null, requiredActions: input.requiredActions, otp: false });
    return id;
  }
  async sendActionsEmail(userId: string, actions: string[]) {
    this.emails.push({ userId, actions });
  }
  async setEnabled(userId: string, enabled: boolean) {
    const u = this.users.get(userId);
    if (u) u.enabled = enabled;
  }
  async logout(userId: string) {
    this.loggedOut.push(userId);
  }
  async hasOtp(userId: string) {
    return this.users.get(userId)?.otp ?? false;
  }
  async removeOtp(userId: string) {
    const u = this.users.get(userId);
    if (u) u.otp = false;
  }
  async addRequiredActions(userId: string, actions: string[]) {
    const u = this.users.get(userId);
    if (u) u.requiredActions = Array.from(new Set([...u.requiredActions, ...actions]));
  }
  async setPassword() {}

  // Tiện ích test: thêm người dùng đã có OTP
  addUser(email: string, otp = false): string {
    const id = randomUUID();
    this.users.set(id, { id, email, enabled: true, displayName: null, requiredActions: [], otp });
    return id;
  }
}
