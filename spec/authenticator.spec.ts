import { describe, expect, it, onTestFinished, vi } from 'vitest';

import { OidcAuthenticator } from '#authenticator';
import { parseConfig } from '#config';
import { TrustedIssuer } from '#issuer';

import { startFakeIssuer } from './fixtures/issuer';

const AUDIENCE = 'https://registry.example.com';

/** options for {@link createAuthenticator} */
interface AuthenticatorOptions {
  /** the clock, in epoch milliseconds */
  readNowMs?: () => number;
  /** how long, in seconds, a verified identity stays cached */
  jwtCacheTtlSeconds?: number;
}

/**
 * builds an authenticator trusting one loopback issuer
 * @param issuerUrl the trusted issuer
 * @param options the clock and cache lifetime
 * @returns an authenticator over that single issuer
 */
function createAuthenticator(
  issuerUrl: string,
  options?: AuthenticatorOptions,
): OidcAuthenticator {
  return new OidcAuthenticator({
    config: parseConfig({
      jwtCacheTtlSeconds: options?.jwtCacheTtlSeconds,
      issuers: [
        {
          id: 'fake',
          issuer: issuerUrl,
          allowInsecureHttp: true,
          audience: AUDIENCE,
          usernameTemplate: 'ci:{repository}',
          groupTemplates: ['ci-org:{repository_owner}'],
          matchClaim: 'repository',
          allow: [{ repository: 'acme/*' }],
        },
      ],
    }),
    readNowMs: options?.readNowMs,
  });
}

describe('cl:OidcAuthenticator', () => {
  describe('mt:authenticateToken', () => {
    it('should map a verified token of a configured issuer to its identity', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const authenticator = createAuthenticator(fakeIssuer.url);
      const token = await fakeIssuer.signToken({
        aud: AUDIENCE,
        repository: 'acme/app',
        repository_owner: 'acme',
      });

      const result = await authenticator.authenticateToken(token);

      expect(result).toEqual({
        issuerId: 'fake',
        name: 'ci:acme/app',
        groups: ['ci-org:acme'],
      });
    });

    it('should answer null for a non-JWT or a token of an unconfigured issuer', async () => {
      await using fakeIssuer = await startFakeIssuer();
      await using otherIssuer = await startFakeIssuer();
      const authenticator = createAuthenticator(fakeIssuer.url);
      const otherToken = await otherIssuer.signToken({
        aud: AUDIENCE,
        repository: 'acme/app',
      });

      const result = await Promise.all([
        authenticator.authenticateToken('verdaccio-issued-token'),
        authenticator.authenticateToken(otherToken),
      ]);

      expect({ result, requestedPaths: otherIssuer.requestedPaths }).toEqual({
        result: [null, null],
        requestedPaths: [],
      });
    });

    it('should reject a verified token no allow entry admits', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const authenticator = createAuthenticator(fakeIssuer.url);
      const token = await fakeIssuer.signToken({
        aud: AUDIENCE,
        repository: 'evil/app',
      });

      const result = authenticator.authenticateToken(token);

      await expect(result).rejects.toMatchObject({
        code: 'OIDC_NOT_ALLOWED',
      });
    });

    it('should serve a repeated token from the cache without re-verifying until the cache expires', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const clock = { nowMs: Date.now() };
      const verifyToken = vi.spyOn(TrustedIssuer.prototype, 'verifyToken');
      const authenticator = createAuthenticator(fakeIssuer.url, {
        readNowMs: () => clock.nowMs,
      });
      const token = await fakeIssuer.signToken({
        aud: AUDIENCE,
        repository: 'acme/app',
        repository_owner: 'acme',
      });

      const first = await authenticator.authenticateToken(token);
      const cached = await authenticator.authenticateToken(token);
      const verificationsWhileCached = verifyToken.mock.calls.length;
      clock.nowMs += 300_000;
      const expired = await authenticator.authenticateToken(token);

      expect({
        identities: [first, cached, expired],
        verificationsWhileCached,
        verifications: verifyToken.mock.calls.length,
      }).toEqual({
        identities: Array.from({ length: 3 }, () => ({
          issuerId: 'fake',
          name: 'ci:acme/app',
          groups: ['ci-org:acme'],
        })),
        verificationsWhileCached: 1,
        verifications: 2,
      });
    });

    it('should verify a token again once it passes exp under a longer cache ttl, and reject it as expired', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      onTestFinished(() => {
        vi.useRealTimers();
      });
      await using fakeIssuer = await startFakeIssuer();
      const verifyToken = vi.spyOn(TrustedIssuer.prototype, 'verifyToken');
      const authenticator = createAuthenticator(fakeIssuer.url, {
        jwtCacheTtlSeconds: 3600,
      });
      const token = await fakeIssuer.signToken({
        aud: AUDIENCE,
        repository: 'acme/app',
        repository_owner: 'acme',
      });

      const first = await authenticator.authenticateToken(token);
      // past the five-minute token life and the 30 s clock tolerance, well inside the hour-long ttl
      vi.setSystemTime(Date.now() + 400_000);
      const expired = await authenticator
        .authenticateToken(token)
        .catch((exception: unknown) => exception);

      expect({
        first,
        expired,
        verifications: verifyToken.mock.calls.length,
      }).toEqual({
        first: {
          issuerId: 'fake',
          name: 'ci:acme/app',
          groups: ['ci-org:acme'],
        },
        expired: expect.objectContaining({
          code: 'OIDC_TOKEN_INVALID',
          meta: { issuerId: 'fake', reason: 'ERR_JWT_EXPIRED' },
        }),
        verifications: 2,
      });
    });
  });
});
