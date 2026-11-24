import { createRemoteJWKSet, jwtVerify } from 'jose';

import { resolveAlgorithms } from '#algorithms';
import { discoverIssuer } from '#discovery';
import { OidcError } from '#errors';

import type { JWTVerifyGetKey } from 'jose';

import type { Claims, ResolvedIssuer } from '#types';

/** construction parameters for {@link TrustedIssuer} */
export interface TrustedIssuerParams {
  /** the resolved issuer config */
  issuer: ResolvedIssuer;
  /** allowed clock drift, in seconds, on exp and nbf */
  clockToleranceSeconds: number;
  /** minimum interval, in seconds, between re-discoveries */
  discoveryCooldownSeconds: number;
  /** the clock, in epoch milliseconds */
  readNowMs?: () => number;
}

interface KeySource {
  jwks: JWTVerifyGetKey;
  algorithms: string[];
}

interface DiscoveryAttempt {
  promise: Promise<KeySource>;
  startedAtMs: number;
  isSettled: boolean;
}

const MS_PER_SECOND = 1000;

// jose codes for failures in finding the signing key rather than in the token itself
const keyResolutionErrorCodes = new Set([
  'ERR_JOSE_GENERIC',
  'ERR_JWKS_INVALID',
  'ERR_JWKS_NO_MATCHING_KEY',
  'ERR_JWKS_TIMEOUT',
]);

/** verifies ID tokens of one configured issuer against its discovered JWKS */
export class TrustedIssuer {
  readonly #issuer: ResolvedIssuer;
  readonly #clockToleranceSeconds: number;
  readonly #discoveryCooldownMs: number;
  readonly #readNowMs: () => number;
  /** the last key source discovery produced, kept until a replacement succeeds */
  #keySource?: KeySource;
  /** the latest discovery, in flight or settled */
  #discoveryAttempt?: DiscoveryAttempt;

  /**
   * creates a verifier for one issuer; discovery runs lazily on first use
   * @param params the issuer config and timing options
   */
  constructor(params: TrustedIssuerParams) {
    const {
      issuer,
      clockToleranceSeconds,
      discoveryCooldownSeconds,
      readNowMs = Date.now,
    } = params;

    this.#issuer = issuer;
    this.#clockToleranceSeconds = clockToleranceSeconds;
    this.#discoveryCooldownMs = discoveryCooldownSeconds * MS_PER_SECOND;
    this.#readNowMs = readNowMs;
  }

  /** the resolved issuer config */
  public get config(): ResolvedIssuer {
    return this.#issuer;
  }

  /**
   * verifies a token's signature, issuer, audience and expiry, re-discovering once when the signing key cannot be resolved
   * @param token the raw ID token
   * @returns the verified claims
   * @throws {OidcError} OIDC_TOKEN_INVALID when the token fails verification
   * @throws {OidcError} OIDC_DISCOVERY_FAILED when the issuer's discovery cannot be fetched or advertises no safe algorithm
   */
  public async verifyToken(token: string): Promise<Claims> {
    const usedKeySource = await this.#readKeySource().catch(
      (exception: unknown) => {
        throw this.#toTokenError(exception);
      },
    );

    try {
      return await this.#verifyWithKeySource(token, usedKeySource);
    } catch (exception) {
      const refreshedKeySource = isKeyResolutionError(exception)
        ? this.#refreshKeySource(usedKeySource)
        : undefined;

      if (!refreshedKeySource) {
        throw this.#toTokenError(exception);
      }

      try {
        return await this.#verifyWithKeySource(token, await refreshedKeySource);
      } catch (retryException) {
        throw this.#toTokenError(retryException);
      }
    }
  }

  /**
   * verifies a token with one key source
   * @param token the raw ID token
   * @param keySource the JWKS and accepted algorithms
   * @returns the verified claims
   */
  async #verifyWithKeySource(
    token: string,
    keySource: KeySource,
  ): Promise<Claims> {
    const { payload } = await jwtVerify(token, keySource.jwks, {
      issuer: this.#issuer.issuer,
      audience: this.#issuer.audience,
      algorithms: keySource.algorithms,
      clockTolerance: this.#clockToleranceSeconds,
      requiredClaims: ['exp'],
    });

    return payload;
  }

  /**
   * returns the last working key source, or the first discovery while none has succeeded yet
   * @returns the key source to verify with
   */
  async #readKeySource(): Promise<KeySource> {
    if (this.#keySource) {
      return this.#keySource;
    }

    const attempt = this.#discoveryAttempt;

    // a failed first discovery is retried once the cooldown has passed
    return attempt && (!attempt.isSettled || !this.#isCooledDown(attempt))
      ? attempt.promise
      : this.#startDiscovery();
  }

  /**
   * re-discovers after a key-resolution failure, sharing a refresh another request already started or finished
   * @param usedKeySource the key source that could not resolve the signing key
   * @returns the refreshed key source, or undefined while the cooldown blocks re-discovery
   */
  #refreshKeySource(usedKeySource: KeySource): Promise<KeySource> | undefined {
    const attempt = this.#discoveryAttempt;

    if (this.#keySource && this.#keySource !== usedKeySource) {
      return Promise.resolve(this.#keySource);
    }

    if (attempt && !attempt.isSettled) {
      return attempt.promise;
    }

    return attempt && !this.#isCooledDown(attempt)
      ? undefined
      : this.#startDiscovery();
  }

  /**
   * checks whether an attempt is old enough to be replaced
   * @param attempt the latest attempt
   * @returns true once the discovery cooldown has passed
   */
  #isCooledDown(attempt: DiscoveryAttempt): boolean {
    return this.#readNowMs() - attempt.startedAtMs >= this.#discoveryCooldownMs;
  }

  /**
   * starts discovery, records it as the shared attempt and adopts its key source only when it succeeds
   * @returns the key source promise
   */
  async #startDiscovery(): Promise<KeySource> {
    const attempt: DiscoveryAttempt = {
      promise: this.#discoverKeySource(),
      startedAtMs: this.#readNowMs(),
      isSettled: false,
    };

    // a failed re-discovery keeps the previous key source in service
    attempt.promise
      .then((keySource) => {
        attempt.isSettled = true;
        this.#keySource = keySource;
      })
      .catch(() => {
        attempt.isSettled = true;
      });
    this.#discoveryAttempt = attempt;

    return attempt.promise;
  }

  /**
   * builds the key source from config or discovery
   * @returns the JWKS and accepted algorithms
   * @throws {OidcError} OIDC_DISCOVERY_FAILED when discovery offers no safe algorithm
   */
  async #discoverKeySource(): Promise<KeySource> {
    const {
      issuer,
      jwksUri,
      algorithms: configured,
      allowInsecureHttp,
    } = this.#issuer;

    if (jwksUri) {
      return {
        jwks: createRemoteJWKSet(new URL(jwksUri)),
        algorithms: resolveAlgorithms({ configured }),
      };
    }

    const metadata = await discoverIssuer(issuer, { allowInsecureHttp });
    const algorithms = resolveAlgorithms({
      configured,
      discovered: metadata.algorithms,
    });

    if (algorithms.length === 0) {
      throw new OidcError(
        'OIDC_DISCOVERY_FAILED',
        `issuer "${this.#issuer.id}" advertises no safe signing algorithm`,
        { meta: { issuerId: this.#issuer.id } },
      );
    }

    return { jwks: createRemoteJWKSet(new URL(metadata.jwksUri)), algorithms };
  }

  /**
   * wraps a verification failure, keeping discovery errors as they are
   * @param exception the failure
   * @returns the error to throw
   */
  #toTokenError(exception: unknown): OidcError {
    if (exception instanceof OidcError) {
      return exception;
    }

    const { code } = exception as { code?: string };

    return new OidcError(
      'OIDC_TOKEN_INVALID',
      `token from issuer "${this.#issuer.id}" failed verification: ${(exception as Error).message}`,
      { cause: exception, meta: { issuerId: this.#issuer.id, reason: code } },
    );
  }
}

/**
 * tells key-resolution failures, which justify re-discovery, from failures caused by the token
 * @param exception the verification failure
 * @returns true when the signing key could not be resolved
 */
function isKeyResolutionError(exception: unknown): boolean {
  const { code } = exception as { code?: unknown };

  // a network failure while fetching the JWKS carries no jose code
  return typeof code !== 'string' || keyResolutionErrorCodes.has(code);
}
