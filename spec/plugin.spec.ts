import { describe, expect, it, vi } from 'vitest';

import { OidcError } from '#errors';
import OidcAuthPlugin from '#plugin';

import type { Response } from 'express';

import type { VerdaccioAuthModule, VerdaccioHost } from '#fallback';
import type {
  AuthMiddlewareHelpers,
  Logger,
  RequestHandler,
  VerdaccioConfig,
  VerdaccioRequest,
} from '#types';

type LogFn = Logger['warn'];

const helpers: AuthMiddlewareHelpers = {
  createAnonymousRemoteUser: () => ({
    name: undefined,
    groups: ['$all', '$anonymous'],
  }),
  createRemoteUser: (name, groups) => ({ name, groups }),
};

const coreHandler = vi.fn<RequestHandler>((_request, _response, next) =>
  next(),
);
const host: VerdaccioHost = {
  version: '7.1.0',
  authModule: {
    Auth: class {
      public async init(): Promise<void> {}

      public apiJWTmiddleware(): RequestHandler {
        return coreHandler;
      }
    },
  },
};

const githubIssuer = {
  id: 'gha',
  issuer: 'https://token.actions.githubusercontent.com',
  audience: 'https://registry.example.com',
  usernameTemplate: 'gha:{repository}',
  groupTemplates: [],
  matchClaim: 'repository',
  allow: [{ repository: 'acme/app' }],
};
const pluginConfig = { issuers: [githubIssuer] };
const verdaccioConfig = {
  secret: 'secret',
  auth: { 'auth-oidc': pluginConfig },
};

describe('cl:OidcAuthPlugin', () => {
  describe('mt:constructor', () => {
    it('should warn about every template that starts with a claim', () => {
      const logger = {
        info: vi.fn<LogFn>(),
        warn: vi.fn<LogFn>(),
        error: vi.fn<LogFn>(),
      } satisfies Logger;

      const result = new OidcAuthPlugin(
        {
          issuers: [
            {
              ...githubIssuer,
              usernameTemplate: '{repository}',
              groupTemplates: ['{repository_owner}', 'gha-org:{repository}'],
            },
          ],
        },
        { config: verdaccioConfig, logger, resolveHost: () => host },
      );

      expect({ plugin: result, warnings: logger.warn.mock.calls }).toEqual({
        plugin: expect.any(OidcAuthPlugin),
        warnings: [
          [
            {
              issuerId: 'gha',
              field: 'usernameTemplate',
              template: '{repository}',
            },
            expect.any(String),
          ],
          [
            {
              issuerId: 'gha',
              field: 'groupTemplates',
              template: '{repository_owner}',
            },
            expect.any(String),
          ],
        ],
      });
    });

    it('should log and exit the process when core auth fails to load its plugins', async () => {
      const logger = {
        info: vi.fn<LogFn>(),
        warn: vi.fn<LogFn>(),
        error: vi.fn<LogFn>(),
      } satisfies Logger;
      const exitProcess = vi.fn<(code: number) => void>();
      const failingAuthModule: VerdaccioAuthModule = {
        Auth: class {
          public async init(): Promise<void> {
            throw new Error('htpasswd file is unreadable');
          }

          public apiJWTmiddleware(): RequestHandler {
            return coreHandler;
          }
        },
      };

      const result = new OidcAuthPlugin(pluginConfig, {
        config: verdaccioConfig,
        logger,
        resolveHost: () => ({ ...host, authModule: failingAuthModule }),
        exitProcess,
      });

      await vi.waitFor(() => {
        expect(exitProcess).toHaveBeenCalled();
      });
      expect({
        plugin: result,
        errors: logger.error.mock.calls,
        exits: exitProcess.mock.calls,
      }).toEqual({
        plugin: expect.any(OidcAuthPlugin),
        errors: [
          [
            { code: undefined, err: 'htpasswd file is unreadable' },
            expect.any(String),
          ],
        ],
        exits: [[1]],
      });
    });

    it.each([
      {
        case: 'an invalid config',
        config: { issuers: [] },
        resolveHost: () => host,
        code: 'OIDC_CONFIG_INVALID',
      },
      {
        case: 'an unresolvable Verdaccio host',
        config: pluginConfig,
        resolveHost: () => {
          throw new OidcError(
            'OIDC_FALLBACK_UNAVAILABLE',
            'cannot find the running Verdaccio',
          );
        },
        code: 'OIDC_FALLBACK_UNAVAILABLE',
      },
    ])(
      'should throw, log and exit on $case',
      async ({ config, resolveHost, code }) => {
        const logger = {
          info: vi.fn<LogFn>(),
          warn: vi.fn<LogFn>(),
          error: vi.fn<LogFn>(),
        } satisfies Logger;
        const exitProcess = vi.fn<(code: number) => void>();

        const result = () =>
          new OidcAuthPlugin(config, {
            config: verdaccioConfig,
            logger,
            resolveHost,
            exitProcess,
          });

        expect(result).toThrow(expect.objectContaining({ code }));
        await vi.waitFor(() => {
          expect(exitProcess).toHaveBeenCalled();
        });
        expect({
          errors: logger.error.mock.calls,
          exits: exitProcess.mock.calls,
        }).toEqual({
          errors: [[{ code, err: expect.any(String) }, expect.any(String)]],
          exits: [[1]],
        });
      },
    );

    it('should end the process with code 1 by default after a startup failure', async () => {
      const exit = vi
        .spyOn(process, 'exit')
        .mockImplementation((() => undefined) as typeof process.exit);
      const logger = {
        info: vi.fn<LogFn>(),
        warn: vi.fn<LogFn>(),
        error: vi.fn<LogFn>(),
      } satisfies Logger;

      const result = () =>
        new OidcAuthPlugin(
          { issuers: [] },
          { config: verdaccioConfig, logger, resolveHost: () => host },
        );

      expect(result).toThrow(
        expect.objectContaining({ code: 'OIDC_CONFIG_INVALID' }),
      );
      await vi.waitFor(() => {
        expect(exit).toHaveBeenCalled();
      });
      expect(exit.mock.calls).toEqual([[1]]);
    });

    it('should start no fallback when loaded by its own fallback, so the outer guard rejects it', async () => {
      const logger = {
        info: vi.fn<LogFn>(),
        warn: vi.fn<LogFn>(),
        error: vi.fn<LogFn>(),
      } satisfies Logger;
      const exitProcess = vi.fn<(code: number) => void>();
      const innerResolveHost = vi.fn(() => host);
      const reloadingAuthModule: VerdaccioAuthModule = {
        Auth: class {
          public plugins: unknown[];

          constructor(config: VerdaccioConfig, authLogger: Logger) {
            this.plugins = [
              new OidcAuthPlugin(pluginConfig, {
                config,
                logger: authLogger,
                resolveHost: innerResolveHost,
              }),
            ];
          }

          public async init(): Promise<void> {}

          public apiJWTmiddleware(): RequestHandler {
            return coreHandler;
          }
        },
      };

      const plugin = new OidcAuthPlugin(pluginConfig, {
        config: { secret: 'secret', auth: { 'ci-oidc': pluginConfig } },
        logger,
        resolveHost: () => ({ ...host, authModule: reloadingAuthModule }),
        exitProcess,
      });
      await vi.waitFor(() => {
        expect(exitProcess).toHaveBeenCalled();
      });

      expect({
        plugin,
        innerHostResolutions: innerResolveHost.mock.calls,
        errors: logger.error.mock.calls,
        exits: exitProcess.mock.calls,
      }).toEqual({
        plugin: expect.any(OidcAuthPlugin),
        innerHostResolutions: [],
        errors: [
          [
            { code: 'OIDC_FALLBACK_UNAVAILABLE', err: expect.any(String) },
            expect.any(String),
          ],
        ],
        exits: [[1]],
      });
    });

    it('should hand core auth every auth plugin except its own keys and ignore entries that are not plugins', async () => {
      const logger = {
        info: vi.fn<LogFn>(),
        warn: vi.fn<LogFn>(),
        error: vi.fn<LogFn>(),
      } satisfies Logger;
      const exitProcess = vi.fn<(code: number) => void>();
      const authSections: unknown[] = [];
      const authModule: VerdaccioAuthModule = {
        Auth: class {
          public plugins = [null, () => undefined, { authenticate: vi.fn() }];

          constructor(config: VerdaccioConfig) {
            authSections.push(config.auth);
          }

          public async init(): Promise<void> {}

          public apiJWTmiddleware(): RequestHandler {
            return coreHandler;
          }
        },
      };
      const plugin = new OidcAuthPlugin(pluginConfig, {
        config: {
          secret: 'secret',
          auth: {
            'htpasswd': { file: './htpasswd' },
            'auth-oidc': pluginConfig,
            'verdaccio-auth-oidc': pluginConfig,
          },
        },
        logger,
        resolveHost: () => ({ ...host, authModule }),
        exitProcess,
      });
      const request = {
        headers: {},
        pause: vi.fn(),
        resume: vi.fn(),
      } as Partial<VerdaccioRequest> as VerdaccioRequest;
      const response = { locals: {} } as Partial<Response> as Response;

      await new Promise<void>((resolve) => {
        plugin.apiJWTmiddleware(helpers)(request, response, () => resolve());
      });

      expect({
        authSections,
        errors: logger.error.mock.calls,
        exits: exitProcess.mock.calls,
      }).toEqual({
        authSections: [{ htpasswd: { file: './htpasswd' } }],
        errors: [],
        exits: [],
      });
    });
  });

  describe('mt:authenticate', () => {
    it('should decline every password login so it falls through to the next auth plugin', () => {
      const plugin = new OidcAuthPlugin(pluginConfig, {
        config: verdaccioConfig,
        logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
        resolveHost: () => host,
      });
      const callback = vi.fn();

      plugin.authenticate('alice', 'password', callback);

      expect(callback.mock.calls).toEqual([[null, false]]);
    });
  });

  describe('mt:apiJWTmiddleware', () => {
    it('should hand a request without an OIDC token to Verdaccio core auth', async () => {
      const logger = {
        info: vi.fn<LogFn>(),
        warn: vi.fn<LogFn>(),
        error: vi.fn<LogFn>(),
      } satisfies Logger;
      const plugin = new OidcAuthPlugin(pluginConfig, {
        config: verdaccioConfig,
        logger,
        resolveHost: () => host,
      });
      const middleware = plugin.apiJWTmiddleware(helpers);
      const request = {
        headers: { authorization: 'Bearer verdaccio-issued' },
        pause: vi.fn(),
        resume: vi.fn(),
      } as Partial<VerdaccioRequest> as VerdaccioRequest;
      const response = { locals: {} } as Partial<Response> as Response;

      await new Promise<void>((resolve) => {
        middleware(request, response, () => resolve());
      });

      expect(coreHandler).toHaveBeenCalledWith(
        request,
        response,
        expect.any(Function),
      );
    });
  });
});
