import {
  mkdtempSync,
  mkdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it, vi } from 'vitest';

import {
  createFallbackAuth,
  findVerdaccioRoot,
  isFallbackConfig,
  resolveHostAuthOptions,
  resolveVerdaccioHost,
  startFallbackHandler,
} from '#fallback';

import type {
  VerdaccioAuth,
  VerdaccioAuthModule,
  VerdaccioAuthOptions,
} from '#fallback';
import type { Logger, RequestHandler, VerdaccioConfig } from '#types';

interface TemporaryDirectory extends Disposable {
  path: string;
}

const logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} satisfies Logger;

/**
 * creates a scratch directory removed on dispose
 * @returns the directory's real path
 */
function createTemporaryDirectory(): TemporaryDirectory {
  const path = realpathSync(
    mkdtempSync(join(tmpdir(), 'verdaccio-auth-oidc-host-')),
  );

  return {
    path,
    [Symbol.dispose]: () => rmSync(path, { recursive: true, force: true }),
  };
}

/**
 * writes a file, creating its parent directories
 * @param path where to write, relative parents included
 * @param content the text to store
 */
function writeFile(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

/**
 * lays out a minimal Verdaccio package with a bin and its own `@verdaccio/auth`
 * @param directory where the fake Verdaccio package lives
 * @param version what its package.json declares
 * @param authModuleSource the code of its `@verdaccio/auth` entry
 */
function writeVerdaccioPackage(
  directory: string,
  version: string,
  authModuleSource = 'exports.Auth = class Auth {};',
): void {
  writeFile(
    join(directory, 'package.json'),
    JSON.stringify({ name: 'verdaccio', version }),
  );
  writeFile(join(directory, 'bin', 'verdaccio'), '');
  // a nested manifest without a name, as Verdaccio's build folders carry
  writeFile(
    join(directory, 'build', 'package.json'),
    JSON.stringify({ type: 'module' }),
  );
  writeFile(join(directory, 'build', 'lib', 'cli.js'), '');
  writeFile(
    join(directory, 'node_modules', '@verdaccio', 'auth', 'package.json'),
    JSON.stringify({ name: '@verdaccio/auth', main: 'index.js' }),
  );
  writeFile(
    join(directory, 'node_modules', '@verdaccio', 'auth', 'index.js'),
    authModuleSource,
  );
}

/**
 * builds a core auth module whose instances report their construction and load a fixed plugin list
 * @param params what each instance does
 * @param params.onConstruct receives the config and options of each construction
 * @param params.plugins the plugins each instance reports as loaded; defaults to none
 * @returns a module exporting that Auth class
 */
function createAuthModule(params: {
  onConstruct?: (
    config: VerdaccioConfig,
    options?: VerdaccioAuthOptions,
  ) => void;
  plugins?: unknown[];
}): VerdaccioAuthModule {
  const { onConstruct, plugins = [] } = params;
  const handler: RequestHandler = vi.fn();

  return {
    Auth: class implements VerdaccioAuth {
      public plugins = plugins;

      constructor(
        config: VerdaccioConfig,
        _logger: Logger,
        options?: VerdaccioAuthOptions,
      ) {
        onConstruct?.(config, options);
      }

      public async init(): Promise<void> {}

      public apiJWTmiddleware(): RequestHandler {
        return handler;
      }
    },
  };
}

describe('fn:findVerdaccioRoot', () => {
  it('should follow a linked bin directory to the Verdaccio package that owns it', () => {
    using directory = createTemporaryDirectory();
    const packageDirectory = join(directory.path, 'node_modules', 'verdaccio');
    const linkedBinDirectory = join(directory.path, 'bin');
    writeVerdaccioPackage(packageDirectory, '6.11.1');
    // a junction links directories on Windows without the symlink privilege; POSIX ignores the type
    symlinkSync(join(packageDirectory, 'bin'), linkedBinDirectory, 'junction');

    const result = findVerdaccioRoot(join(linkedBinDirectory, 'verdaccio'));

    expect(result).toEqual({ directory: packageDirectory, version: '6.11.1' });
  });

  it('should find Verdaccio as the root package from a nested build entry, as in the Docker image', () => {
    using directory = createTemporaryDirectory();
    writeVerdaccioPackage(directory.path, '7.1.0');

    const result = findVerdaccioRoot(
      join(directory.path, 'build', 'lib', 'cli.js'),
    );

    expect(result).toEqual({ directory: directory.path, version: '7.1.0' });
  });

  it('should fail with OIDC_FALLBACK_UNAVAILABLE when there is no entry script', () => {
    const result = () => findVerdaccioRoot(undefined);

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_FALLBACK_UNAVAILABLE',
        cause: new Error('Node was started without an entry script'),
      }),
    );
  });

  it('should fail with OIDC_FALLBACK_UNAVAILABLE when the entry script does not exist', () => {
    using directory = createTemporaryDirectory();
    const entryPath = join(directory.path, 'missing-cli.js');

    const result = () => findVerdaccioRoot(entryPath);

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_FALLBACK_UNAVAILABLE',
        meta: { entryPath },
      }),
    );
  });

  it('should fail with OIDC_FALLBACK_UNAVAILABLE when no Verdaccio package sits above the entry', () => {
    using directory = createTemporaryDirectory();
    const entryPath = join(directory.path, 'pm2', 'container.js');
    writeFile(entryPath, '');

    const result = () => findVerdaccioRoot(entryPath);

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_FALLBACK_UNAVAILABLE',
        meta: { entryPath },
      }),
    );
  });
});

describe('fn:resolveVerdaccioHost', () => {
  it('should load the core Auth class of the Verdaccio install behind a bin', () => {
    const bin = fileURLToPath(
      new URL('../node_modules/verdaccio-6/bin/verdaccio', import.meta.url),
    );

    const result = resolveVerdaccioHost(bin);

    expect(result).toEqual({
      version: expect.stringMatching(/^6\./),
      authModule: expect.objectContaining({ Auth: expect.any(Function) }),
    });
  });

  it('should fail with OIDC_FALLBACK_UNAVAILABLE when the @verdaccio/auth of Verdaccio cannot be loaded', () => {
    using directory = createTemporaryDirectory();
    writeVerdaccioPackage(
      directory.path,
      '6.11.1',
      "throw new Error('broken build');",
    );

    const result = () =>
      resolveVerdaccioHost(join(directory.path, 'bin', 'verdaccio'));

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_FALLBACK_UNAVAILABLE',
        meta: { directory: directory.path, version: '6.11.1' },
      }),
    );
  });
});

describe('fn:resolveHostAuthOptions', () => {
  it.each([
    { version: '6.1.0', expected: undefined },
    { version: '6.1.1', expected: undefined },
    { version: '6.1.2', expected: { legacyMergeConfigs: true } },
    { version: '6.11.2', expected: { legacyMergeConfigs: true } },
    { version: '6.12.0-next.1', expected: { legacyMergeConfigs: true } },
    { version: '7.0.0', expected: undefined },
    { version: '7.1.0', expected: undefined },
    { version: '8.0.0-next-8.15', expected: undefined },
  ])(
    'should mirror the options Verdaccio $version passes to its core Auth',
    ({ version, expected }) => {
      const result = resolveHostAuthOptions(version);

      expect(result).toEqual(expected);
    },
  );

  it.each([
    { case: 'a Verdaccio older than 6.1.0', version: '6.0.5' },
    { case: 'a 5.x Verdaccio', version: '5.31.0' },
    { case: 'an unparsable version', version: 'latest' },
  ])('should refuse $case', ({ version }) => {
    const result = () => resolveHostAuthOptions(version);

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_FALLBACK_UNAVAILABLE',
        meta: { version },
      }),
    );
  });
});

describe('fn:createFallbackAuth', () => {
  it('should build core auth with the host options over every auth plugin except this one', () => {
    const constructions: Array<{
      config: VerdaccioConfig;
      options?: VerdaccioAuthOptions;
    }> = [];

    createFallbackAuth({
      host: {
        version: '6.11.1',
        authModule: createAuthModule({
          onConstruct: (config, options) => {
            constructions.push({ config, options });
          },
        }),
      },
      config: {
        secret: 'secret',
        auth: {
          'htpasswd': { file: './htpasswd' },
          'auth-oidc': { issuers: [] },
        },
      },
      logger,
      excludedPluginIds: ['auth-oidc'],
    });

    expect(
      constructions.map(({ config, options }) => ({
        secret: config.secret,
        auth: config.auth,
        options,
      })),
    ).toEqual([
      {
        secret: 'secret',
        auth: { htpasswd: { file: './htpasswd' } },
        options: { legacyMergeConfigs: true },
      },
    ]);
  });

  it.each([
    { version: '7.1.0', warnings: [] },
    {
      version: '8.0.0',
      warnings: [[{ version: '8.0.0' }, expect.any(String)]],
    },
    {
      version: '8.0.0-next-8.15',
      warnings: [[{ version: '8.0.0-next-8.15' }, expect.any(String)]],
    },
  ])(
    'should warn only when Verdaccio $version is newer than 7.x',
    ({ version, warnings }) => {
      const warn = vi.fn<Logger['warn']>();

      createFallbackAuth({
        host: { version, authModule: createAuthModule({}) },
        config: { secret: 'secret', auth: null },
        logger: { ...logger, warn },
        excludedPluginIds: ['auth-oidc'],
      });

      expect(warn.mock.calls).toEqual(warnings);
    },
  );

  it('should mark only the config it hands to core auth as a fallback config', () => {
    const constructions: VerdaccioConfig[] = [];
    const config: VerdaccioConfig = {
      secret: 'secret',
      auth: { 'auth-oidc': { issuers: [] } },
    };

    createFallbackAuth({
      host: {
        version: '7.1.0',
        authModule: createAuthModule({
          onConstruct: (fallbackConfig) => {
            constructions.push(fallbackConfig);
          },
        }),
      },
      config,
      logger,
      excludedPluginIds: ['auth-oidc'],
    });

    expect({
      isHandedConfigMarked: constructions.map(isFallbackConfig),
      isOriginalMarked: isFallbackConfig(config),
    }).toEqual({ isHandedConfigMarked: [true], isOriginalMarked: false });
  });

  it.each([
    {
      case: 'only this plugin is configured',
      auth: { 'auth-oidc': { issuers: [] } },
    },
    { case: 'no auth section exists', auth: null },
  ])(
    'should run core auth with auth: null and the host options when $case',
    ({ auth }) => {
      const constructions: Array<{
        config: VerdaccioConfig;
        options?: VerdaccioAuthOptions;
      }> = [];

      createFallbackAuth({
        host: {
          version: '7.1.0',
          authModule: createAuthModule({
            onConstruct: (config, options) => {
              constructions.push({ config, options });
            },
          }),
        },
        config: { secret: 'secret', auth },
        logger,
        excludedPluginIds: ['auth-oidc'],
      });

      expect(
        constructions.map(({ config, options }) => ({
          auth: config.auth,
          options,
        })),
      ).toEqual([{ auth: null, options: undefined }]);
    },
  );

  it.each([
    {
      case: 'core auth cannot be constructed, e.g. without a secret',
      version: '7.1.0',
      error: expect.objectContaining({ message: 'secret is required' }),
    },
    {
      case: 'the host is older than 6.1.0',
      version: '6.0.0',
      error: expect.objectContaining({ code: 'OIDC_FALLBACK_UNAVAILABLE' }),
    },
  ])('should throw at once when $case', ({ version, error }) => {
    const create = () =>
      createFallbackAuth({
        host: {
          version,
          authModule: createAuthModule({
            onConstruct: () => {
              throw new Error('secret is required');
            },
          }),
        },
        config: { auth: null },
        logger,
        excludedPluginIds: ['auth-oidc'],
      });

    expect(create).toThrow(error);
  });
});

describe('fn:startFallbackHandler', () => {
  const { Auth } = createAuthModule({});
  const auth = new Auth({}, logger);

  it("should return core auth's middleware once its plugins have loaded", async () => {
    const result = await startFallbackHandler(auth, () => false);

    expect(result).toBe(auth.apiJWTmiddleware());
  });

  it('should reject with OIDC_FALLBACK_UNAVAILABLE when core auth loads this plugin again, e.g. under a renamed key', async () => {
    const self = { name: 'verdaccio-auth-oidc' };
    const { Auth: SelfLoadingAuth } = createAuthModule({ plugins: [{}, self] });

    const result = startFallbackHandler(
      new SelfLoadingAuth({}, logger),
      (plugin) => plugin === self,
    );

    await expect(result).rejects.toEqual(
      expect.objectContaining({ code: 'OIDC_FALLBACK_UNAVAILABLE' }),
    );
  });
});
