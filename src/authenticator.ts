import { decodeJwt } from 'jose';

import { IdentityCache } from '#cache';
import { resolveIdentity } from '#identity';
import { TrustedIssuer } from '#issuer';

import type { Identity, ResolvedPluginConfig } from '#types';

/** construction parameters for {@link OidcAuthenticator} */
export interface OidcAuthenticatorParams {
  /** the resolved plugin config */
  config: ResolvedPluginConfig;
  /** the clock, in epoch milliseconds */
  readNowMs?: () => number;
}

/** routes bearer tokens to their configured issuer and maps verified tokens to identities */
export class OidcAuthenticator {
  readonly #issuersByUrl: Map<string, TrustedIssuer>;
  readonly #cache: IdentityCache;

  /**
   * creates an authenticator over every configured issuer
   * @param params the resolved config and clock
   */
  constructor(params: OidcAuthenticatorParams) {
    const { config, readNowMs } = params;

    this.#issuersByUrl = new Map(
      config.issuers.map((issuer) => [
        issuer.issuer,
        new TrustedIssuer({
          issuer,
          clockToleranceSeconds: config.clockToleranceSeconds,
          discoveryCooldownSeconds: config.discoveryCooldownSeconds,
          readNowMs,
        }),
      ]),
    );
    this.#cache = new IdentityCache({
      ttlSeconds: config.jwtCacheTtlSeconds,
      maxEntries: config.jwtCacheMaxEntries,
      readNowMs,
    });
  }

  /**
   * authenticates a bearer token when it belongs to a configured issuer
   * @param token the raw bearer token
   * @returns the identity, or null when the token is not an ID token of a configured issuer
   */
  public async authenticateToken(token: string): Promise<Identity | null> {
    const cached = this.#cache.get(token);
    if (cached) {
      return cached;
    }

    const issuer = this.#issuersByUrl.get(readUnverifiedIssuer(token) ?? '');
    if (!issuer) {
      return null;
    }

    const claims = await issuer.verifyToken(token);
    const identity = resolveIdentity(issuer.config, claims);

    // exp is present because verification requires it
    this.#cache.set(token, identity, claims.exp!);

    return identity;
  }
}

/**
 * reads the iss claim without verifying the token, only to route it
 * @param token the raw bearer token
 * @returns the claimed issuer, or undefined for anything that is not a JWT with an iss claim
 */
function readUnverifiedIssuer(token: string): string | undefined {
  try {
    return decodeJwt(token).iss;
  } catch {
    // not a JWT: the token belongs to Verdaccio or another plugin
    return undefined;
  }
}
