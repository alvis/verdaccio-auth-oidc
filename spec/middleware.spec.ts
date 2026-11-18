import { describe, expect, it, vi } from 'vitest';

import { OidcError } from '#errors';
import { createOidcMiddleware } from '#middleware';

import type { Response } from 'express';

import type {
  Identity,
  Logger,
  RemoteUser,
  RequestHandler,
  VerdaccioRequest,
} from '#types';

type LogFn = Logger['warn'];

const identity: Identity = {
  issuerId: 'fake',
  name: 'ci:acme/app',
  groups: ['ci-org:acme'],
};

const createRemoteUser = (name: string, groups: string[]): RemoteUser => ({
  name,
  groups: [...groups, '$authenticated'],
});

/**
 * builds a paused-stream request carrying an authorization header
 * @param authorization the header value, if any
 * @returns a request whose pause and resume are recorded
 */
function createRequest(authorization?: string): VerdaccioRequest {
  return {
    headers: authorization ? { authorization } : {},
    pause: vi.fn(),
    resume: vi.fn(),
  } as Partial<VerdaccioRequest> as VerdaccioRequest;
}

/**
 * builds a response recording its status and JSON body
 * @returns a response whose status and json calls are recorded
 */
function createResponse(): Response {
  const response: Partial<Response> = { locals: {} };
  response.status = vi.fn<Response['status']>(() => response as Response);
  response.json = vi.fn<Response['json']>(() => response as Response);

  return response as Response;
}

describe('fn:createOidcMiddleware', () => {
  it('should attach the identity of a verified OIDC token as the remote user', async () => {
    const authenticateToken = vi.fn(async () => identity);
    const middleware = createOidcMiddleware({
      authenticateToken,
      createRemoteUser,
      readFallbackHandler: vi.fn(),
      logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    });
    const request = createRequest('Bearer token');
    const response = createResponse();

    await new Promise<void>((resolve) => {
      middleware(request, response, () => resolve());
    });

    expect({
      tokens: authenticateToken.mock.calls,
      requestUser: request.remote_user,
      responseUser: response.locals.remote_user,
      isResumed: vi.mocked(request.resume).mock.calls.length > 0,
    }).toEqual({
      tokens: [['token']],
      requestUser: {
        name: 'ci:acme/app',
        groups: ['ci-org:acme', '$authenticated'],
      },
      responseUser: {
        name: 'ci:acme/app',
        groups: ['ci-org:acme', '$authenticated'],
      },
      isResumed: true,
    });
  });

  it('should answer 401 with the fixed body and log a warning when verification fails', async () => {
    const logger = {
      info: vi.fn<LogFn>(),
      warn: vi.fn<LogFn>(),
      error: vi.fn<LogFn>(),
    } satisfies Logger;
    const middleware = createOidcMiddleware({
      authenticateToken: async () => {
        throw new OidcError('OIDC_NOT_ALLOWED', 'not allowed', {
          meta: { issuerId: 'fake' },
        });
      },
      createRemoteUser,
      readFallbackHandler: vi.fn(),
      logger,
    });
    const request = createRequest('Bearer token');
    const response = createResponse();
    const next = vi.fn();

    middleware(request, response, next);
    await vi.waitFor(() => {
      expect(response.json).toHaveBeenCalled();
    });

    expect({
      status: vi.mocked(response.status).mock.calls,
      body: vi.mocked(response.json).mock.calls,
      warnings: logger.warn.mock.calls,
      isResumed: vi.mocked(request.resume).mock.calls.length > 0,
      nextCalls: next.mock.calls,
    }).toEqual({
      status: [[401]],
      body: [
        [{ error: 'unauthorized', reason: 'oidc token verification failed' }],
      ],
      warnings: [
        [
          {
            code: 'OIDC_NOT_ALLOWED',
            meta: { issuerId: 'fake' },
            err: 'not allowed',
          },
          expect.any(String),
        ],
      ],
      isResumed: true,
      nextCalls: [],
    });
  });

  it.each([
    { case: 'no authorization header' },
    { case: 'basic auth', authorization: 'Basic dXNlcjpwYXNz' },
    {
      case: 'a bearer token of no configured issuer',
      authorization: 'Bearer abc',
    },
  ])(
    'should hand a request with $case to the fallback',
    async ({ authorization }) => {
      const fallback = vi.fn<RequestHandler>((_request, _response, next) =>
        next(),
      );
      const middleware = createOidcMiddleware({
        authenticateToken: async () => null,
        createRemoteUser,
        readFallbackHandler: async () => fallback,
        logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });
      const request = createRequest(authorization);
      const response = createResponse();

      await new Promise<void>((resolve) => {
        middleware(request, response, () => resolve());
      });

      expect({
        fallbackCalls: fallback.mock.calls,
        remoteUser: request.remote_user,
        isResumed: vi.mocked(request.resume).mock.calls.length > 0,
      }).toEqual({
        fallbackCalls: [[request, response, expect.any(Function)]],
        remoteUser: undefined,
        isResumed: true,
      });
    },
  );

  it('should pass a fallback start-up failure to next', async () => {
    const failure = new OidcError(
      'OIDC_FALLBACK_UNAVAILABLE',
      'core auth failed to start',
    );
    const middleware = createOidcMiddleware({
      authenticateToken: async () => null,
      createRemoteUser,
      readFallbackHandler: async () => {
        throw failure;
      },
      logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    });
    const request = createRequest('Basic dXNlcjpwYXNz');
    const response = createResponse();

    const result = await new Promise<unknown>((resolve) => {
      middleware(request, response, resolve);
    });

    expect(result).toBe(failure);
  });
});
