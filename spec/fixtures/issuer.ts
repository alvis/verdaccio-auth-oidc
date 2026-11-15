import { createServer } from 'node:http';

import { SignJWT, exportJWK, generateKeyPair } from 'jose';

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import type { CryptoKey, JWK, JWTPayload } from 'jose';

/** an in-process OIDC issuer serving discovery, a JWKS and token signing */
export interface FakeIssuer extends AsyncDisposable {
  /** the issuer URL, equal to the iss claim of every signed token */
  url: string;
  /** signs a token with the current key; iss, iat and exp default to this issuer and a five-minute life */
  signToken: (
    claims: JWTPayload,
    options?: SignTokenOptions,
  ) => Promise<string>;
  /** paths requested so far, in order */
  requestedPaths: string[];
  /** makes discovery answer 503 until switched back, as during an issuer outage */
  setDiscoveryAvailable: (isAvailable: boolean) => void;
  /** replaces the algorithms discovery advertises in id_token_signing_alg_values_supported */
  setAdvertisedAlgorithms: (algorithms: string[]) => void;
  /** switches to a new signing key, published at a new JWKS path that discovery advertises from then on */
  rotateKey: () => Promise<void>;
  /**
   * holds every request to a path until released, as a slow network would
   * @returns a function that answers every held and future request normally
   */
  holdRequests: (path: string) => () => void;
  /** resets the connection of every request to a path, as a network failure would */
  dropRequests: (path: string) => void;
}

/** options for {@link FakeIssuer.signToken} */
export interface SignTokenOptions {
  /** whether the token carries an exp claim; defaults to true */
  hasExpiry?: boolean;
}

interface SigningKey {
  privateKey: CryptoKey;
  jwk: JWK;
}

const ALGORITHM = 'RS256';
const TOKEN_LIFETIME_SECONDS = 300;
const HTTP_OK = 200;
const HTTP_NOT_FOUND = 404;
const HTTP_UNAVAILABLE = 503;

/**
 * generates a signing key and its public JWK
 * @param kid the key id published in the JWKS and set in token headers
 * @returns the private key and the public JWK
 */
async function generateSigningKey(kid: string): Promise<SigningKey> {
  const { privateKey, publicKey } = await generateKeyPair(ALGORITHM);
  const jwk = {
    ...(await exportJWK(publicKey)),
    kid,
    alg: ALGORITHM,
    use: 'sig',
  };

  return { privateKey, jwk };
}

/**
 * starts a fake issuer on a random local port
 * @returns the running issuer, closed on dispose
 */
export async function startFakeIssuer(): Promise<FakeIssuer> {
  // each key generation is published at /jwks/<generation>, starting from 1
  const keys = [await generateSigningKey('key-1')];
  const requestedPaths: string[] = [];
  const state = {
    isDiscoveryAvailable: true,
    advertisedAlgorithms: [ALGORITHM],
  };
  const heldPaths = new Map<string, Promise<void>>();
  const droppedPaths = new Set<string>();

  const server = createServer((request, response) => {
    const path = request.url ?? '';
    requestedPaths.push(path);

    if (droppedPaths.has(path)) {
      request.socket.destroy();

      return;
    }

    void (heldPaths.get(path) ?? Promise.resolve()).then(async () =>
      serve(request, response),
    );
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${port}`;
  const readJwksPath = (): string => `/jwks/${keys.length}`;

  const signToken = async (
    claims: JWTPayload,
    options?: SignTokenOptions,
  ): Promise<string> => {
    const { privateKey, jwk } = keys.at(-1)!;
    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiry =
      options?.hasExpiry === false
        ? {}
        : { exp: nowSeconds + TOKEN_LIFETIME_SECONDS };

    return new SignJWT({ iss: url, iat: nowSeconds, ...expiry, ...claims })
      .setProtectedHeader({ alg: ALGORITHM, kid: jwk.kid, typ: 'JWT' })
      .sign(privateKey);
  };

  /**
   * answers discovery and JWKS requests
   * @param request the incoming request
   * @param response the outgoing response
   */
  async function serve(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const reply = (status: number, body: unknown): void => {
      response.writeHead(status, { 'content-type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    const route = `${request.method} ${request.url}`;
    const jwksGeneration = /^GET \/jwks\/(\d+)$/.exec(route)?.[1];
    const jwksKey = keys[Number(jwksGeneration) - 1];

    if (jwksKey) {
      return reply(HTTP_OK, { keys: [jwksKey.jwk] });
    }

    switch (route) {
      case 'GET /.well-known/openid-configuration':
        if (!state.isDiscoveryAvailable) {
          return reply(HTTP_UNAVAILABLE, { error: 'unavailable' });
        }

        return reply(HTTP_OK, {
          issuer: url,
          jwks_uri: `${url}${readJwksPath()}`,
          id_token_signing_alg_values_supported: state.advertisedAlgorithms,
        });
      default:
        return reply(HTTP_NOT_FOUND, { error: 'not found' });
    }
  }

  return {
    url,
    signToken,
    requestedPaths,
    setDiscoveryAvailable: (isAvailable) => {
      state.isDiscoveryAvailable = isAvailable;
    },
    setAdvertisedAlgorithms: (algorithms) => {
      state.advertisedAlgorithms = algorithms;
    },
    rotateKey: async () => {
      keys.push(await generateSigningKey(`key-${keys.length + 1}`));
    },
    holdRequests: (path) => {
      const { promise, resolve } = Promise.withResolvers<void>();
      heldPaths.set(path, promise);

      return () => {
        heldPaths.delete(path);
        resolve();
      };
    },
    dropRequests: (path) => {
      droppedPaths.add(path);
    },
    [Symbol.asyncDispose]: async () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      }),
  };
}
