import { readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

import { OidcError } from '#errors';

import type { Logger, RequestHandler, VerdaccioConfig } from '#types';

/** the part of a `@verdaccio/auth` `Auth` instance the fallback uses */
export interface VerdaccioAuth {
  /** loads the configured auth plugins */
  init: () => Promise<void>;
  /** builds Verdaccio's core bearer/basic middleware */
  apiJWTmiddleware: () => RequestHandler;
  /** the loaded auth plugins */
  plugins?: unknown[];
}

/** the third `Auth` constructor argument, which `@verdaccio/auth` reads since 8.0.0-next-8.15 */
export interface VerdaccioAuthOptions {
  /** whether each auth plugin receives its config merged over the full Verdaccio config */
  legacyMergeConfigs: boolean;
}

/** Verdaccio's core auth class */
export type VerdaccioAuthConstructor = new (
  config: VerdaccioConfig,
  logger: Logger,
  options?: VerdaccioAuthOptions,
) => VerdaccioAuth;

/** the part of the `@verdaccio/auth` module the fallback uses, whose `Auth` export name Verdaccio fixes */
export type VerdaccioAuthModule = Record<'Auth', VerdaccioAuthConstructor>;

/** the running Verdaccio install the fallback mirrors */
export interface VerdaccioHost {
  /** the version in Verdaccio's package.json */
  version: string;
  /** the `@verdaccio/auth` module Verdaccio itself loads */
  authModule: VerdaccioAuthModule;
}

/** resolves the running Verdaccio install */
export type VerdaccioHostResolver = () => VerdaccioHost;

/** a Verdaccio package root found above an entry script */
export interface VerdaccioRoot {
  /** the directory holding Verdaccio's package.json */
  directory: string;
  /** the version in that package.json */
  version: string;
}

/** the package.json fields the host walk-up reads */
interface PackageManifest {
  name?: unknown;
  version?: unknown;
}

/** construction parameters for {@link createFallbackAuth} */
export interface FallbackAuthParams {
  /** the running Verdaccio */
  host: VerdaccioHost;
  /** the full Verdaccio configuration */
  config: VerdaccioConfig;
  /** Verdaccio's logger */
  logger: Logger;
  /** the `auth:` keys that load this plugin, excluded from the fallback */
  excludedPluginIds: string[];
}

// marks the config the fallback hands to core auth, so an instance of this plugin loaded through it starts no fallback of its own
const FALLBACK_CONFIG_MARKER = Symbol.for(
  'verdaccio-auth-oidc/fallback-config',
);

// the first release running @verdaccio/auth in its core API
const SUPPORTED_SINCE = '6.1.0';
// the first release whose core passes { legacyMergeConfigs: true }; 6.1.0 and 6.1.1 pass nothing
const LEGACY_MERGE_SINCE = '6.1.2';
// 7.x core (@verdaccio/server) passes nothing again
const LEGACY_MERGE_UNTIL = '7.0.0';
const versionRegex = /^(\d+)\.(\d+)\.(\d+)/;

/**
 * finds the nearest `verdaccio` package root above an entry script, following symlinks first
 * @param entryPath the script Node started, normally Verdaccio's bin or, in the Docker image, a file inside the Verdaccio package itself
 * @returns the package directory and version
 * @throws {OidcError} OIDC_FALLBACK_UNAVAILABLE when no package.json named verdaccio sits above the entry script
 */
export function findVerdaccioRoot(
  entryPath: string | undefined,
): VerdaccioRoot {
  const root = findVerdaccioRootFrom(dirname(realpathOrThrow(entryPath)));

  if (!root) {
    throw new OidcError(
      'OIDC_FALLBACK_UNAVAILABLE',
      `cannot find the running Verdaccio: no package.json named verdaccio above ${String(entryPath)}; start Verdaccio through its own bin`,
      { meta: { entryPath } },
    );
  }

  return root;
}

/**
 * resolves the running Verdaccio install and the `@verdaccio/auth` it loads, so the fallback matches the host's version
 * @param entryPath the script Node started; defaults to `process.argv[1]`
 * @returns the host version and its core auth module
 * @throws {OidcError} OIDC_FALLBACK_UNAVAILABLE when Verdaccio or its core auth cannot be resolved
 */
export function resolveVerdaccioHost(
  entryPath: string | undefined = process.argv[1],
): VerdaccioHost {
  const { directory, version } = findVerdaccioRoot(entryPath);

  try {
    const authModule = createRequire(join(directory, 'package.json'))(
      '@verdaccio/auth',
    ) as VerdaccioAuthModule;

    return { version, authModule };
  } catch (exception) {
    throw new OidcError(
      'OIDC_FALLBACK_UNAVAILABLE',
      `cannot load @verdaccio/auth from Verdaccio ${version} at ${directory}: ${(exception as Error).message}`,
      { cause: exception, meta: { directory, version } },
    );
  }
}

/**
 * returns the options the host's own core passes to `new Auth`, so other auth plugins see the same config shape on API requests as on login
 * @param version the running Verdaccio's version
 * @returns `{ legacyMergeConfigs: true }` for 6.1.2 to 6.x, nothing for 6.1.0, 6.1.1 and 7.x or later
 * @throws {OidcError} OIDC_FALLBACK_UNAVAILABLE for a version below 6.1.0, whose core does not run `@verdaccio/auth`, or an unparsable version
 */
export function resolveHostAuthOptions(
  version: string,
): VerdaccioAuthOptions | undefined {
  const parts = parseVersion(version);

  if (!parts || isBefore(parts, SUPPORTED_SINCE)) {
    throw new OidcError(
      'OIDC_FALLBACK_UNAVAILABLE',
      `Verdaccio ${version} is not supported; verdaccio-auth-oidc needs Verdaccio ${SUPPORTED_SINCE} or later`,
      { meta: { version } },
    );
  }

  const isMergingHost =
    !isBefore(parts, LEGACY_MERGE_SINCE) && isBefore(parts, LEGACY_MERGE_UNTIL);

  return isMergingHost ? { legacyMergeConfigs: true } : undefined;
}

/**
 * checks whether a Verdaccio config is the one a fallback handed to core auth
 * @param config the config an auth plugin was constructed with
 * @returns true when this plugin is being loaded by its own fallback
 */
export function isFallbackConfig(config: VerdaccioConfig): boolean {
  return Reflect.get(config, FALLBACK_CONFIG_MARKER) === true;
}

/**
 * constructs Verdaccio's own core auth over every auth plugin except this one, the way the host constructs its own
 *
 * Construction is synchronous, so an unsupported host, a missing secret or a broken core module throws while Verdaccio loads this plugin.
 * @param params the host, config and exclusion rules
 * @returns core auth, not yet initialized
 * @throws {OidcError} OIDC_FALLBACK_UNAVAILABLE for an unsupported host
 */
export function createFallbackAuth(params: FallbackAuthParams): VerdaccioAuth {
  const { host, config, logger, excludedPluginIds } = params;

  const remainingAuth = Object.fromEntries(
    Object.entries(config.auth ?? {}).filter(
      ([pluginId]) => !excludedPluginIds.includes(pluginId),
    ),
  );

  // inherit the live config, methods included, and override only the auth section
  const fallbackConfig = Object.create(config, {
    auth: {
      value: Object.keys(remainingAuth).length > 0 ? remainingAuth : null,
      enumerable: true,
      writable: true,
    },
  }) as VerdaccioConfig;
  Object.defineProperty(fallbackConfig, FALLBACK_CONFIG_MARKER, {
    value: true,
  });

  const authOptions = resolveHostAuthOptions(host.version);

  return authOptions
    ? new host.authModule.Auth(fallbackConfig, logger, authOptions)
    : new host.authModule.Auth(fallbackConfig, logger);
}

/**
 * loads core auth's plugins and builds the core middleware that handles every non-OIDC request
 * @param auth core auth from {@link createFallbackAuth}
 * @param isSelf recognizes an instance of this plugin, as a guard against delegating to itself
 * @returns the core middleware
 * @throws {OidcError} OIDC_FALLBACK_UNAVAILABLE when core auth loaded this plugin again, e.g. under a renamed key
 */
export async function startFallbackHandler(
  auth: VerdaccioAuth,
  isSelf: (plugin: unknown) => boolean,
): Promise<RequestHandler> {
  await auth.init();

  if (auth.plugins?.some(isSelf)) {
    throw new OidcError(
      'OIDC_FALLBACK_UNAVAILABLE',
      'the fallback auth would load verdaccio-auth-oidc again; register it under the auth key auth-oidc',
    );
  }

  return auth.apiJWTmiddleware();
}

/**
 * reads the numeric major, minor and patch of a version
 * @param version a semantic version, possibly with a pre-release suffix
 * @returns the three numbers, or undefined when the version does not start with them
 */
function parseVersion(version: string): number[] | undefined {
  return versionRegex.exec(version)?.slice(1).map(Number);
}

/**
 * checks whether a parsed version sorts before a known release
 * @param parts the major, minor and patch to check
 * @param release a release version written as major.minor.patch
 * @returns true when parts is the older version
 */
function isBefore(parts: number[], release: string): boolean {
  const releaseParts = parseVersion(release)!;
  const index = parts.findIndex(
    (part, position) => part !== releaseParts[position],
  );

  return index >= 0 && parts[index]! < releaseParts[index]!;
}

/**
 * walks up from a directory to the nearest package.json named verdaccio
 * @param directory the directory to check first
 * @returns the Verdaccio root, or undefined when the walk reaches the file system root
 */
function findVerdaccioRootFrom(directory: string): VerdaccioRoot | undefined {
  const manifest = readManifest(join(directory, 'package.json'));
  if (manifest?.name === 'verdaccio' && typeof manifest.version === 'string') {
    return { directory, version: manifest.version };
  }

  const parent = dirname(directory);

  return parent === directory ? undefined : findVerdaccioRootFrom(parent);
}

/**
 * resolves an entry script to its real path
 * @param entryPath the script Node started
 * @returns the real path, with every symlink followed
 * @throws {OidcError} OIDC_FALLBACK_UNAVAILABLE when there is no entry script or it does not exist
 */
function realpathOrThrow(entryPath: string | undefined): string {
  try {
    if (!entryPath) {
      throw new Error('Node was started without an entry script');
    }

    return realpathSync(entryPath);
  } catch (exception) {
    throw new OidcError(
      'OIDC_FALLBACK_UNAVAILABLE',
      `cannot find the running Verdaccio from the entry script ${String(entryPath)}: ${(exception as Error).message}`,
      { cause: exception, meta: { entryPath } },
    );
  }
}

/**
 * reads a package.json when one exists
 * @param path the package.json path
 * @returns its name and version, or undefined when the file is missing or not JSON
 */
function readManifest(path: string): PackageManifest | undefined {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as PackageManifest;
  } catch {
    // no manifest at this level: keep walking up
    return undefined;
  }
}
