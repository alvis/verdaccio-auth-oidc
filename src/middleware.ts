import type { NextFunction, Response } from 'express';

import type {
  AuthMiddlewareHelpers,
  Identity,
  Logger,
  RequestHandler,
  VerdaccioRequest,
} from '#types';

/** construction parameters for {@link createOidcMiddleware} */
export interface OidcMiddlewareParams {
  /** authenticates a bearer token, resolving null when it is not an OIDC token of a configured issuer */
  authenticateToken: (token: string) => Promise<Identity | null>;
  /** Verdaccio's helper that builds `req.remote_user` */
  createRemoteUser: AuthMiddlewareHelpers['createRemoteUser'];
  /** resolves Verdaccio's own core auth middleware, for every non-OIDC request */
  readFallbackHandler: () => Promise<RequestHandler>;
  /** Verdaccio's logger */
  logger: Logger;
}

const HTTP_UNAUTHORIZED = 401;
const bearerRegex = /^bearer\s+(\S+)$/i;
const unauthorizedBody = {
  error: 'unauthorized',
  reason: 'oidc token verification failed',
};

/**
 * creates the Express handler that replaces Verdaccio's core bearer/basic handling
 * @param params token authentication, Verdaccio helpers and the fallback
 * @returns a handler that authenticates OIDC tokens and delegates every other request to Verdaccio's core auth
 */
export function createOidcMiddleware(
  params: OidcMiddlewareParams,
): RequestHandler {
  const { authenticateToken, createRemoteUser, readFallbackHandler, logger } =
    params;

  return (request, response, next) => {
    request.pause();

    void handleRequest({
      request,
      response,
      next,
      token: readBearerToken(request.headers.authorization),
    });
  };

  /**
   * authenticates the request or hands it to the fallback
   * @param context the request, response, next callback and bearer token
   * @param context.request the incoming request
   * @param context.response the outgoing response
   * @param context.next Express's continuation
   * @param context.token the bearer token, if any
   */
  async function handleRequest(context: {
    request: VerdaccioRequest;
    response: Response;
    next: NextFunction;
    token: string | undefined;
  }): Promise<void> {
    const { request, response, next, token } = context;

    try {
      const identity = token ? await authenticateToken(token) : null;

      if (identity) {
        const remoteUser = createRemoteUser(identity.name, identity.groups);
        request.remote_user = remoteUser;
        response.locals.remote_user = remoteUser;
        request.resume();
        next();

        return;
      }
    } catch (exception) {
      const { code, meta } = exception as { code?: unknown; meta?: unknown };
      logger.warn(
        { code, meta, err: (exception as Error).message },
        'oidc token rejected: @{err}',
      );
      request.resume();
      response.status(HTTP_UNAUTHORIZED).json(unauthorizedBody);

      return;
    }

    try {
      const fallback = await readFallbackHandler();
      request.resume();
      fallback(request, response, next);
    } catch (exception) {
      request.resume();
      next(exception);
    }
  }
}

/**
 * extracts a bearer token from an authorization header
 * @param authorization the header value
 * @returns the token, or undefined for any other scheme
 */
function readBearerToken(
  authorization: string | undefined,
): string | undefined {
  return authorization ? bearerRegex.exec(authorization)?.[1] : undefined;
}
