// COMPOSITION ROOT: nơi DUY NHẤT biết lớp cụ thể nào hiện thực interface nào.
// Awilix tạo đối tượng và tiêm phụ thuộc theo tên (InjectionMode.PROXY: constructor nhận một object "cradle").
// Test thay thế bất kỳ phụ thuộc nào bằng overrides (ví dụ idp giả, tokenVerifier giả).
import {
  asClass,
  asFunction,
  asValue,
  createContainer,
  InjectionMode,
  type AwilixContainer,
  type Resolver,
} from 'awilix';
import {
  CachingAuthorizer,
  ClientCredentialsTokenProvider,
  createLogger,
  HealthState,
  JoseTokenVerifier,
  type Authorizer,
  type Logger,
  type TokenVerifier,
} from '@ol/node-kit';
import type pg from 'pg';
import { AuthzService } from './application/authz-service.js';
import { BootstrapService } from './application/bootstrap-service.js';
import { GroupService } from './application/group-service.js';
import { MeService } from './application/me-service.js';
import type { IdentityProvider, UnitOfWork } from './application/ports.js';
import { RoleService } from './application/role-service.js';
import { TenantService } from './application/tenant-service.js';
import { UserService } from './application/user-service.js';
import { dbOptions, type AppConfig } from './config.js';
import { createDb, createPool, DrizzleUnitOfWork } from './infrastructure/db/database.js';
import { KeycloakAdminClient } from './infrastructure/keycloak/keycloak-admin.js';

export interface Cradle {
  config: AppConfig;
  logger: Logger;
  health: HealthState;
  pool: pg.Pool;
  uow: UnitOfWork;
  idp: IdentityProvider;
  tokenVerifier: TokenVerifier;
  authorizer: Authorizer;
  authzService: AuthzService;
  userService: UserService;
  meService: MeService;
  tenantService: TenantService;
  groupService: GroupService;
  roleService: RoleService;
  bootstrapService: BootstrapService;
}

export function buildContainer(
  config: AppConfig,
  options: { pool?: pg.Pool; overrides?: Partial<Record<keyof Cradle, Resolver<unknown>>> } = {},
): AwilixContainer<Cradle> {
  const container = createContainer<Cradle>({ injectionMode: InjectionMode.PROXY, strict: true });
  const pool = options.pool ?? createPool(dbOptions(config));
  const realmUrl = `${config.KEYCLOAK_INTERNAL_URL}/realms/${config.KEYCLOAK_REALM}`;

  container.register({
    config: asValue(config),
    logger: asValue(createLogger({ service: 'ol-iam-service', level: config.LOG_LEVEL })),
    health: asValue(new HealthState()),
    pool: asValue(pool),
    uow: asValue(new DrizzleUnitOfWork(createDb(pool))),

    // Danh tính của chính IAM khi gọi Keycloak Admin API
    idp: asFunction(
      () =>
        new KeycloakAdminClient({
          baseUrl: config.KEYCLOAK_INTERNAL_URL,
          realm: config.KEYCLOAK_REALM,
          clientId: config.INVITE_CLIENT_ID,
          redirectUri: `${config.APP_URL}/`,
          tokenProvider: new ClientCredentialsTokenProvider({
            tokenEndpoint: `${realmUrl}/protocol/openid-connect/token`,
            clientId: config.IAM_CLIENT_ID,
            clientSecret: config.IAM_CLIENT_SECRET,
          }),
        }),
    ).singleton(),

    // Xác minh token: issuer là URL công khai, JWKS tải qua URL nội bộ
    tokenVerifier: asValue(
      new JoseTokenVerifier({
        issuer: [
          config.OIDC_ISSUER,
          ...(config.OIDC_INTERNAL_ISSUER ? [config.OIDC_INTERNAL_ISSUER] : []),
        ],
        audience: config.OIDC_AUDIENCE,
        jwksUri: `${realmUrl}/protocol/openid-connect/certs`,
      }),
    ),

    authzService: asClass(AuthzService).singleton(),
    // Route của chính IAM dùng quyết định cục bộ (không gọi HTTP vào chính mình) + cache 30 giây
    authorizer: asFunction(
      ({ authzService, logger }: Cradle) => new CachingAuthorizer(authzService, { logger }),
    ).singleton(),

    userService: asClass(UserService).singleton(),
    meService: asClass(MeService).singleton(),
    tenantService: asClass(TenantService).singleton(),
    groupService: asClass(GroupService).singleton(),
    roleService: asClass(RoleService).singleton(),
    bootstrapService: asClass(BootstrapService).singleton(),
  });

  if (options.overrides) container.register(options.overrides as Record<string, Resolver<unknown>>);
  return container;
}
