import { describe, expect, it, vi } from 'vitest';

import { OidcError } from '#errors';
import { createOidcMiddleware } from '#middleware';

import type { Response } from 'express';
import type { Mock } from 'vitest';

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

/**
 * lists mock names in the order their calls happened
 * @param mocks the mocks to interleave, by name
 * @returns one name per call, earliest first
 */
function listCallOrder(mocks: Record<string, Mock>): string[] {
  return Object.entries(mocks)
    .flatMap(([name, mock]) =>
      mock.mock.invocationCallOrder.map((order) => ({ name, order })),
    )
    .sort((left, right) => left.order - right.order)
    .map(({ name }) => name);
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
    const next = vi.fn();

    await new Promise<void>((resolve) => {
      next.mockImplementation(() => resolve());
      middleware(request, response, next);
    });

    expect({
      tokens: authenticateToken.mock.calls,
      requestUser: request.remote_user,
      responseUser: response.locals.remote_user,
      callOrder: listCallOrder({
        pause: vi.mocked(request.pause),
        authenticateToken,
        resume: vi.mocked(request.resume),
        next,
      }),
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
      callOrder: ['pause', 'authenticateToken', 'resume', 'next'],
    });
  });

  it('should answer 401 with the fixed body and log a warning when verification fails', async () => {
    const logger = {
      info: vi.fn<LogFn>(),
      warn: vi.fn<LogFn>(),
      error: vi.fn<LogFn>(),
    } satisfies Logger;
    const authenticateToken = vi.fn(async () => {
      throw new OidcError('OIDC_NOT_ALLOWED', 'not allowed', {
        meta: { issuerId: 'fake' },
      });
    });
    const middleware = createOidcMiddleware({
      authenticateToken,
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
      callOrder: listCallOrder({
        pause: vi.mocked(request.pause),
        authenticateToken,
        resume: vi.mocked(request.resume),
        status: vi.mocked(response.status),
        next,
      }),
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
      callOrder: ['pause', 'authenticateToken', 'resume', 'status'],
    });
  });

  it.each([
    { case: 'no authorization header', verifications: [] },
    {
      case: 'basic auth',
      authorization: 'Basic dXNlcjpwYXNz',
      verifications: [],
    },
    {
      case: 'a bearer token of no configured issuer',
      authorization: 'Bearer abc',
      verifications: ['authenticateToken'],
    },
  ])(
    'should hand a request with $case to the fallback',
    async ({ authorization, verifications }) => {
      const fallback = vi.fn<RequestHandler>((_request, _response, next) =>
        next(),
      );
      const authenticateToken = vi.fn(async () => null);
      const middleware = createOidcMiddleware({
        authenticateToken,
        createRemoteUser,
        readFallbackHandler: async () => fallback,
        logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      });
      const request = createRequest(authorization);
      const response = createResponse();
      const next = vi.fn();

      await new Promise<void>((resolve) => {
        next.mockImplementation(() => resolve());
        middleware(request, response, next);
      });

      expect({
        fallbackCalls: fallback.mock.calls,
        remoteUser: request.remote_user,
        callOrder: listCallOrder({
          pause: vi.mocked(request.pause),
          authenticateToken,
          resume: vi.mocked(request.resume),
          fallback,
          next,
        }),
      }).toEqual({
        fallbackCalls: [[request, response, next]],
        remoteUser: undefined,
        callOrder: ['pause', ...verifications, 'resume', 'fallback', 'next'],
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
