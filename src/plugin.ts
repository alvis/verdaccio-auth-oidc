import { OidcAuthenticator } from '#authenticator';
import { parseConfig } from '#config';
import {
  createFallbackAuth,
  isFallbackConfig,
  resolveVerdaccioHost,
  startFallbackHandler,
} from '#fallback';
import { createOidcMiddleware } from '#middleware';
import { listPrefixlessTemplates } from '#template';

import type { VerdaccioHostResolver } from '#fallback';
import type { PrefixlessTemplate } from '#template';
import type {
  AuthMiddlewareHelpers,
  Logger,
  RequestHandler,
  VerdaccioPluginOptions,
} from '#types';

/** plugin constructor options: Verdaccio's options plus test seams Verdaccio never sets */
export interface OidcAuthPluginOptions extends VerdaccioPluginOptions {
  /** resolves the running Verdaccio and its `@verdaccio/auth`; defaults to walking up from `process.argv[1]` */
  resolveHost?: VerdaccioHostResolver;
  /** ends the process after a fatal startup failure; defaults to `process.exit` */
  exitProcess?: (code: number) => void;
  /** the clock, in epoch milliseconds */
  readNowMs?: () => number;
}

/** callback Verdaccio passes to `authenticate` */
export type AuthenticateCallback = (
  error: Error | null,
  groups?: string[] | false,
) => void;

// the `auth:` keys Verdaccio's loaders resolve to this package
const PLUGIN_IDS = ['auth-oidc', 'verdaccio-auth-oidc'];

// brands every instance across module copies, since the plugins folder and node_modules can load this package twice
const PLUGIN_BRAND = Symbol.for('verdaccio-auth-oidc/plugin');

const EXIT_CODE_STARTUP_FAILURE = 1;

/**
 * Verdaccio auth plugin that verifies CI OIDC ID tokens and hands every other request to Verdaccio's core auth
 *
 * Verdaccio's plugin loaders instantiate the module's default export, so this class is the package's default export.
 */
export default class OidcAuthPlugin {
  readonly #authenticator: OidcAuthenticator;
  readonly #logger: Logger;
  readonly #exitProcess: (code: number) => void;
  readonly #fallbackHandler: Promise<RequestHandler>;

  /**
   * validates the config, resolves Verdaccio's core auth and starts the fallback, ending the process on any failure
   *
   * Verdaccio does not await plugin start-up and, for a plugin in its `plugins` folder, logs and skips a constructor error,
   * so every failure here, including one in the asynchronous fallback start, is logged and then exits the process.
   * @param config the plugin's config block, possibly merged with Verdaccio's config
   * @param options Verdaccio's plugin options
   */
  constructor(config: unknown, options: OidcAuthPluginOptions) {
    const {
      config: verdaccioConfig,
      logger,
      resolveHost = resolveVerdaccioHost,
      // eslint-disable-next-line unicorn/no-process-exit -- owner-approved fail-fast: Verdaccio awaits no plugin start-up and skips a failing plugins-folder plugin, so only exiting stops it serving without this plugin
      exitProcess = (code) => process.exit(code),
      readNowMs,
    } = options;

    Object.defineProperty(this, PLUGIN_BRAND, { value: true });
    this.#logger = logger;
    this.#exitProcess = exitProcess;

    try {
      const resolvedConfig = parseConfig(config);
      this.#authenticator = new OidcAuthenticator({
        config: resolvedConfig,
        readNowMs,
      });
      this.#warnPrefixlessTemplates(listPrefixlessTemplates(resolvedConfig));

      // an instance loaded by its own fallback must not start another fallback; the outer instance's guard rejects it
      this.#fallbackHandler = isFallbackConfig(verdaccioConfig)
        ? new Promise<RequestHandler>(() => undefined)
        : startFallbackHandler(
            createFallbackAuth({
              host: resolveHost(),
              config: verdaccioConfig,
              logger,
              excludedPluginIds: PLUGIN_IDS,
            }),
            (plugin) => isOidcAuthPlugin(plugin),
          );
    } catch (exception) {
      this.#failStartup(exception);
      throw exception;
    }

    this.#fallbackHandler.catch((exception: unknown) => {
      this.#failStartup(exception);
    });
  }

  /**
   * declines every password login so it falls through to the next auth plugin
   * @param _user the user name
   * @param _password the password
   * @param callback Verdaccio's callback
   */
  public authenticate(
    _user: string,
    _password: string,
    callback: AuthenticateCallback,
  ): void {
    callback(null, false);
  }

  /**
   * builds the middleware that replaces Verdaccio's core bearer/basic handling
   * @param helpers Verdaccio's remote-user helpers
   * @returns the Express handler
   */
  public apiJWTmiddleware(helpers: AuthMiddlewareHelpers): RequestHandler {
    return createOidcMiddleware({
      authenticateToken: async (token) =>
        this.#authenticator.authenticateToken(token),
      createRemoteUser: helpers.createRemoteUser,
      readFallbackHandler: async () => this.#fallbackHandler,
      logger: this.#logger,
    });
  }

  /**
   * warns about templates whose rendered names the token's claims fully control
   * @param templates the templates with no literal prefix
   */
  #warnPrefixlessTemplates(templates: PrefixlessTemplate[]): void {
    for (const { issuerId, field, source } of templates) {
      this.#logger.warn(
        { issuerId, field, template: source },
        'oidc issuer @{issuerId} has a @{field} entry "@{template}" with no literal prefix, so token claims alone choose the name; prefix it, e.g. "ci:{claim}", to keep OIDC names apart from other users and groups',
      );
    }
  }

  /**
   * logs a startup failure and ends the process once the current call stack has unwound
   * @param exception the failure
   */
  #failStartup(exception: unknown): void {
    const { code } = exception as { code?: unknown };
    this.#logger.error(
      { code, err: (exception as Error).message },
      'verdaccio-auth-oidc failed to start, stopping verdaccio: @{err}',
    );

    // let the host log its own failure first when it catches the same error
    setImmediate(() => this.#exitProcess(EXIT_CODE_STARTUP_FAILURE));
  }
}

/**
 * recognizes an instance of this plugin, including one loaded from another copy of the package
 * @param plugin a loaded auth plugin
 * @returns true for an instance of this plugin
 */
function isOidcAuthPlugin(plugin: unknown): boolean {
  return (
    typeof plugin === 'object' &&
    plugin !== null &&
    Reflect.get(plugin, PLUGIN_BRAND) === true
  );
}
