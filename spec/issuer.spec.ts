import { SignJWT, generateKeyPair } from 'jose';
import { describe, expect, it, vi } from 'vitest';

import { parseConfig } from '#config';
import { TrustedIssuer } from '#issuer';

import { startFakeIssuer } from './fixtures/issuer';

import type { TrustedIssuerParams } from '#issuer';

import type { FakeIssuer } from './fixtures/issuer';

const AUDIENCE = 'https://registry.example.com';
const TOKEN_LIFETIME_SECONDS = 300;
const DISCOVERY_PATH = '/.well-known/openid-configuration';
const JOSE_COOLDOWN_MS = 30_000;

const claims = { aud: AUDIENCE, repository: 'acme/app' };

/**
 * resolves the config of a loopback fake issuer
 * @param url where the loopback issuer listens
 * @param overrides issuer options to set on top of the defaults
 * @returns the resolved issuer
 */
function resolveFakeIssuer(
  url: string,
  overrides?: Record<string, unknown>,
): TrustedIssuerParams['issuer'] {
  const { issuers } = parseConfig({
    issuers: [
      {
        id: 'fake',
        issuer: url,
        allowInsecureHttp: true,
        audience: AUDIENCE,
        usernameTemplate: 'ci:{repository}',
        groupTemplates: [],
        matchClaim: 'repository',
        allow: [{ repository: 'acme/app' }],
        ...overrides,
      },
    ],
  });

  return issuers[0]!;
}

/**
 * counts the requests the issuer received for a path
 * @param issuer the fake issuer
 * @param path the requested path
 * @returns how many requests named the path
 */
function countRequests(issuer: FakeIssuer, path: string): number {
  return issuer.requestedPaths.filter((requested) => requested === path).length;
}

/**
 * signs a token with a key the issuer never published
 * @param issuerUrl the iss claim
 * @returns the token
 */
async function signWithUnknownKey(issuerUrl: string): Promise<string> {
  const { privateKey } = await generateKeyPair('RS256');
  const nowSeconds = Math.floor(Date.now() / 1000);

  return new SignJWT({
    ...claims,
    iss: issuerUrl,
    exp: nowSeconds + TOKEN_LIFETIME_SECONDS,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'unknown-key' })
    .sign(privateKey);
}

describe('cl:TrustedIssuer', () => {
  describe('gt:config', () => {
    it('should expose the resolved issuer config', () => {
      const config = resolveFakeIssuer('http://127.0.0.1:1');
      const issuer = new TrustedIssuer({
        issuer: config,
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 30,
      });

      const result = issuer.config;

      expect(result).toBe(config);
    });
  });

  describe('mt:verifyToken', () => {
    it('should verify a token signed by the discovered key', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const issuer = new TrustedIssuer({
        issuer: resolveFakeIssuer(fakeIssuer.url),
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 30,
      });
      const token = await fakeIssuer.signToken(claims);

      const result = await issuer.verifyToken(token);

      expect(result).toEqual(
        expect.objectContaining({
          iss: fakeIssuer.url,
          repository: 'acme/app',
        }),
      );
    });

    it('should verify with an explicit jwksUri without discovery', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const issuer = new TrustedIssuer({
        issuer: resolveFakeIssuer(fakeIssuer.url, {
          jwksUri: `${fakeIssuer.url}/jwks/1`,
        }),
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 30,
      });
      const token = await fakeIssuer.signToken(claims);

      const result = await issuer.verifyToken(token);

      expect({ result, requestedPaths: fakeIssuer.requestedPaths }).toEqual({
        result: expect.objectContaining({ repository: 'acme/app' }),
        requestedPaths: ['/jwks/1'],
      });
    });

    it('should keep verifying with the working key set when a re-discovery fails', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const issuer = new TrustedIssuer({
        issuer: resolveFakeIssuer(fakeIssuer.url),
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 0,
      });
      const token = await fakeIssuer.signToken(claims);
      const unknownKeyToken = await signWithUnknownKey(fakeIssuer.url);

      await issuer.verifyToken(token);
      fakeIssuer.setDiscoveryAvailable(false);
      const failedRefresh = issuer.verifyToken(unknownKeyToken);
      await expect(failedRefresh).rejects.toMatchObject({
        code: 'OIDC_DISCOVERY_FAILED',
      });
      const result = await issuer.verifyToken(token);

      expect(result).toEqual(
        expect.objectContaining({ repository: 'acme/app' }),
      );
    });

    it('should adopt the re-discovered key set once a re-discovery succeeds', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const issuer = new TrustedIssuer({
        issuer: resolveFakeIssuer(fakeIssuer.url),
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 0,
      });
      await issuer.verifyToken(await fakeIssuer.signToken(claims));
      await fakeIssuer.rotateKey();
      const rotatedToken = await fakeIssuer.signToken(claims);

      const results = [
        await issuer.verifyToken(rotatedToken),
        await issuer.verifyToken(rotatedToken),
      ];

      expect({
        results,
        discoveries: countRequests(fakeIssuer, DISCOVERY_PATH),
      }).toEqual({
        results: [
          expect.objectContaining({ repository: 'acme/app' }),
          expect.objectContaining({ repository: 'acme/app' }),
        ],
        discoveries: 2,
      });
    });

    it('should re-discover once on an unknown kid and respect discoveryCooldownSeconds', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const clock = { nowMs: 1_000_000 };
      const issuer = new TrustedIssuer({
        issuer: resolveFakeIssuer(fakeIssuer.url),
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 30,
        readNowMs: () => clock.nowMs,
      });
      const unknownKeyToken = await signWithUnknownKey(fakeIssuer.url);
      await issuer.verifyToken(await fakeIssuer.signToken(claims));

      const duringCooldown = await issuer
        .verifyToken(unknownKeyToken)
        .catch((exception: unknown) => exception);
      const discoveriesDuringCooldown = countRequests(
        fakeIssuer,
        DISCOVERY_PATH,
      );
      clock.nowMs += 30_000;
      const afterCooldown = await issuer
        .verifyToken(unknownKeyToken)
        .catch((exception: unknown) => exception);

      expect({
        duringCooldown,
        discoveriesDuringCooldown,
        afterCooldown,
        discoveriesAfterCooldown: countRequests(fakeIssuer, DISCOVERY_PATH),
      }).toEqual({
        duringCooldown: expect.objectContaining({
          code: 'OIDC_TOKEN_INVALID',
          meta: { issuerId: 'fake', reason: 'ERR_JWKS_NO_MATCHING_KEY' },
        }),
        discoveriesDuringCooldown: 1,
        afterCooldown: expect.objectContaining({
          code: 'OIDC_TOKEN_INVALID',
          meta: { issuerId: 'fake', reason: 'ERR_JWKS_NO_MATCHING_KEY' },
        }),
        discoveriesAfterCooldown: 2,
      });
    });

    it('should share one re-discovery across concurrent requests', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const issuer = new TrustedIssuer({
        issuer: resolveFakeIssuer(fakeIssuer.url),
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 0,
      });
      await issuer.verifyToken(await fakeIssuer.signToken(claims));
      await fakeIssuer.rotateKey();
      const rotatedToken = await fakeIssuer.signToken(claims);

      const results = await Promise.all([
        issuer.verifyToken(rotatedToken),
        issuer.verifyToken(rotatedToken),
        issuer.verifyToken(rotatedToken),
      ]);

      expect({
        results,
        discoveries: countRequests(fakeIssuer, DISCOVERY_PATH),
      }).toEqual({
        results: Array.from({ length: 3 }, () =>
          expect.objectContaining({ repository: 'acme/app' }),
        ),
        discoveries: 2,
      });
    });

    it('should reuse a key set another request refreshed while its own lookup was still running', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const clock = { nowMs: Date.now() };
      vi.spyOn(Date, 'now').mockImplementation(() => clock.nowMs);
      const issuer = new TrustedIssuer({
        issuer: resolveFakeIssuer(fakeIssuer.url),
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 0,
        readNowMs: () => clock.nowMs,
      });
      await issuer.verifyToken(await fakeIssuer.signToken(claims));
      await fakeIssuer.rotateKey();
      const rotatedToken = await fakeIssuer.signToken(claims);
      const releaseOldKeySet = fakeIssuer.holdRequests('/jwks/1');

      clock.nowMs += JOSE_COOLDOWN_MS;
      const slowRequest = issuer.verifyToken(rotatedToken);
      await vi.waitFor(() => {
        expect(countRequests(fakeIssuer, '/jwks/1')).toBe(2);
      });
      clock.nowMs -= JOSE_COOLDOWN_MS;
      const fastResult = await issuer.verifyToken(rotatedToken);
      releaseOldKeySet();
      const slowResult = await slowRequest;

      expect({
        fastResult,
        slowResult,
        discoveries: countRequests(fakeIssuer, DISCOVERY_PATH),
      }).toEqual({
        fastResult: expect.objectContaining({ repository: 'acme/app' }),
        slowResult: expect.objectContaining({ repository: 'acme/app' }),
        discoveries: 2,
      });
    });

    it('should retry a failed first discovery only once the cooldown has passed', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const clock = { nowMs: 1_000_000 };
      const issuer = new TrustedIssuer({
        issuer: resolveFakeIssuer(fakeIssuer.url),
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 30,
        readNowMs: () => clock.nowMs,
      });
      const token = await fakeIssuer.signToken(claims);
      fakeIssuer.setDiscoveryAvailable(false);

      const failures = [
        await issuer
          .verifyToken(token)
          .catch((exception: unknown) => exception),
        await issuer
          .verifyToken(token)
          .catch((exception: unknown) => exception),
      ];
      const discoveriesDuringCooldown = countRequests(
        fakeIssuer,
        DISCOVERY_PATH,
      );
      fakeIssuer.setDiscoveryAvailable(true);
      clock.nowMs += 30_000;
      const result = await issuer.verifyToken(token);

      expect({ failures, discoveriesDuringCooldown, result }).toEqual({
        failures: [
          expect.objectContaining({ code: 'OIDC_DISCOVERY_FAILED' }),
          expect.objectContaining({ code: 'OIDC_DISCOVERY_FAILED' }),
        ],
        discoveriesDuringCooldown: 1,
        result: expect.objectContaining({ repository: 'acme/app' }),
      });
    });

    it('should re-discover when the key set cannot be fetched', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const issuer = new TrustedIssuer({
        issuer: resolveFakeIssuer(fakeIssuer.url),
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 0,
      });
      const token = await fakeIssuer.signToken(claims);
      fakeIssuer.dropRequests('/jwks/1');

      const result = issuer.verifyToken(token);

      await expect(result).rejects.toMatchObject({
        code: 'OIDC_TOKEN_INVALID',
      });
      expect(countRequests(fakeIssuer, DISCOVERY_PATH)).toBe(2);
    });

    it('should fail with OIDC_DISCOVERY_FAILED when discovery advertises no safe algorithm', async () => {
      await using fakeIssuer = await startFakeIssuer();
      const issuer = new TrustedIssuer({
        issuer: resolveFakeIssuer(fakeIssuer.url),
        clockToleranceSeconds: 30,
        discoveryCooldownSeconds: 30,
      });
      fakeIssuer.setAdvertisedAlgorithms(['HS256', 'none']);
      const token = await fakeIssuer.signToken(claims);

      const result = issuer.verifyToken(token);

      await expect(result).rejects.toMatchObject({
        code: 'OIDC_DISCOVERY_FAILED',
        meta: { issuerId: 'fake' },
      });
    });

    it.each([
      {
        case: 'an expired token',
        reason: 'ERR_JWT_EXPIRED',
        sign: async (issuer: FakeIssuer) =>
          issuer.signToken({
            ...claims,
            exp: Math.floor(Date.now() / 1000) - 3600,
          }),
      },
      {
        case: 'a token without exp',
        reason: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        sign: async (issuer: FakeIssuer) =>
          issuer.signToken(claims, { hasExpiry: false }),
      },
      {
        case: 'a token for another audience',
        reason: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        sign: async (issuer: FakeIssuer) =>
          issuer.signToken({ ...claims, aud: 'https://other.example.com' }),
      },
      {
        case: 'a token from another issuer',
        reason: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        sign: async (issuer: FakeIssuer) =>
          issuer.signToken({ ...claims, iss: 'https://evil.example.com' }),
      },
      {
        case: 'an HS256 token',
        reason: 'ERR_JOSE_ALG_NOT_ALLOWED',
        sign: async (issuer: FakeIssuer) =>
          new SignJWT({ ...claims, iss: issuer.url })
            .setProtectedHeader({ alg: 'HS256', kid: 'key-1' })
            .setExpirationTime('5m')
            .sign(new TextEncoder().encode('a-shared-secret-of-enough-length')),
      },
    ])(
      'should reject $case without re-discovering',
      async ({ reason, sign }) => {
        await using fakeIssuer = await startFakeIssuer();
        const issuer = new TrustedIssuer({
          issuer: resolveFakeIssuer(fakeIssuer.url),
          clockToleranceSeconds: 30,
          discoveryCooldownSeconds: 0,
        });
        const token = await sign(fakeIssuer);

        const result = await issuer
          .verifyToken(token)
          .catch((exception: unknown) => exception);

        expect({
          result,
          discoveries: countRequests(fakeIssuer, DISCOVERY_PATH),
        }).toEqual({
          result: expect.objectContaining({
            code: 'OIDC_TOKEN_INVALID',
            meta: { issuerId: 'fake', reason },
          }),
          discoveries: 1,
        });
      },
    );
  });
});
