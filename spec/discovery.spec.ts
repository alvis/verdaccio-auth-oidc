import { createServer } from 'node:http';

import { describe, expect, it } from 'vitest';

import { discoverIssuer } from '#discovery';

import { startFakeIssuer } from './fixtures/issuer';

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

/** a local HTTP server answering every request with one handler */
interface DocumentServer extends AsyncDisposable {
  /** the server's base URL, without a trailing slash */
  url: string;
  /** paths requested so far, in order */
  requestedPaths: string[];
}

/** answers one request, given the server's base URL */
type DocumentHandler = (
  context: { url: string; request: IncomingMessage },
  response: ServerResponse,
) => void;

/**
 * starts a local server that answers discovery requests with a handler
 * @param handler writes the answer for each request
 * @returns the running server, closed on dispose
 */
async function startDocumentServer(
  handler: DocumentHandler,
): Promise<DocumentServer> {
  const requestedPaths: string[] = [];
  const address = { url: '' };
  const server = createServer((request, response) => {
    requestedPaths.push(request.url ?? '');
    handler({ url: address.url, request }, response);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  address.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    url: address.url,
    requestedPaths,
    [Symbol.asyncDispose]: async () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      }),
  };
}

/**
 * builds a handler answering 200 with a JSON body
 * @param buildBody builds the body from the server's base URL
 * @returns the handler
 */
function replyJson(buildBody: (url: string) => unknown): DocumentHandler {
  return ({ url }, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(buildBody(url)));
  };
}

describe('fn:discoverIssuer', () => {
  it('should read the JWKS endpoint and algorithms of a matching issuer', async () => {
    await using issuer = await startFakeIssuer();

    const result = await discoverIssuer(issuer.url, {
      allowInsecureHttp: true,
    });

    expect(result).toEqual({
      jwksUri: `${issuer.url}/jwks/1`,
      algorithms: ['RS256'],
    });
  });

  it('should accept an issuer URL with a trailing slash and keep only string algorithms', async () => {
    await using server = await startDocumentServer(
      replyJson((url) => ({
        issuer: `${url}/`,
        jwks_uri: 'https://keys.example.com/jwks',
        id_token_signing_alg_values_supported: ['ES256', 42, null],
      })),
    );

    const result = await discoverIssuer(`${server.url}/`);

    expect({ result, requestedPaths: server.requestedPaths }).toEqual({
      result: {
        jwksUri: 'https://keys.example.com/jwks',
        algorithms: ['ES256'],
      },
      requestedPaths: ['/.well-known/openid-configuration'],
    });
  });

  it('should leave algorithms unset when the document advertises none', async () => {
    await using server = await startDocumentServer(
      replyJson((url) => ({
        issuer: url,
        jwks_uri: 'https://keys.example.com/jwks',
      })),
    );

    const result = await discoverIssuer(server.url);

    expect(result).toEqual({
      jwksUri: 'https://keys.example.com/jwks',
      algorithms: undefined,
    });
  });

  it('should reject a plain http jwks_uri unless the issuer opts in', async () => {
    await using issuer = await startFakeIssuer();

    const result = discoverIssuer(issuer.url);

    await expect(result).rejects.toMatchObject({
      code: 'OIDC_DISCOVERY_FAILED',
      meta: {
        issuer: issuer.url,
        url: `${issuer.url}/.well-known/openid-configuration`,
      },
    });
  });

  it.each([
    {
      case: 'a document naming another issuer',
      handler: replyJson(() => ({
        issuer: 'https://evil.example.com',
        jwks_uri: 'https://keys.example.com/jwks',
      })),
    },
    {
      case: 'a document without jwks_uri',
      handler: replyJson((url) => ({ issuer: url })),
    },
    {
      case: 'a jwks_uri that is not a URL',
      handler: replyJson((url) => ({ issuer: url, jwks_uri: 'jwks' })),
    },
    {
      case: 'a jwks_uri that is not a string',
      handler: replyJson((url) => ({ issuer: url, jwks_uri: 42 })),
    },
  ])('should reject $case', async ({ handler }) => {
    await using server = await startDocumentServer(handler);

    const result = discoverIssuer(server.url, { allowInsecureHttp: true });

    await expect(result).rejects.toMatchObject({
      code: 'OIDC_DISCOVERY_FAILED',
      meta: {
        issuer: server.url,
        url: `${server.url}/.well-known/openid-configuration`,
      },
    });
  });

  it.each([
    {
      case: 'a redirect without following it',
      status: 302,
      handler: (({ url }, response) => {
        response.writeHead(302, { location: `${url}/elsewhere` });
        response.end();
      }) satisfies DocumentHandler,
    },
    {
      case: 'a non-200 answer',
      status: 503,
      handler: ((_context, response) => {
        response.writeHead(503);
        response.end();
      }) satisfies DocumentHandler,
    },
  ])('should reject $case', async ({ status, handler }) => {
    await using server = await startDocumentServer(handler);

    const result = discoverIssuer(server.url);

    await expect(result).rejects.toMatchObject({
      code: 'OIDC_DISCOVERY_FAILED',
      meta: { url: `${server.url}/.well-known/openid-configuration`, status },
    });
    expect(server.requestedPaths).toEqual([
      '/.well-known/openid-configuration',
    ]);
  });

  it.each([
    {
      case: 'an answer that is not JSON',
      handler: ((_context, response) => {
        response.writeHead(200, { 'content-type': 'text/html' });
        response.end('<html></html>');
      }) satisfies DocumentHandler,
    },
    {
      case: 'a JSON answer that is not an object',
      handler: replyJson(() => 42),
    },
    {
      case: 'no answer within the timeout',
      handler: (() => undefined) satisfies DocumentHandler,
    },
  ])('should reject $case', async ({ handler }) => {
    await using server = await startDocumentServer(handler);

    const result = discoverIssuer(server.url, { timeoutMs: 100 });

    await expect(result).rejects.toMatchObject({
      code: 'OIDC_DISCOVERY_FAILED',
      meta: { url: `${server.url}/.well-known/openid-configuration` },
    });
  });
});
