import { OidcError } from '#errors';

/** the parts of an OpenID provider configuration this plugin uses */
export interface IssuerMetadata {
  /** the JWKS endpoint */
  jwksUri: string;
  /** advertised ID token signing algorithms, when listed */
  algorithms?: string[];
}

/** options for {@link discoverIssuer} */
export interface DiscoverIssuerOptions {
  /** request timeout in milliseconds */
  timeoutMs?: number;
  /** whether a plain http jwks_uri is accepted; defaults to false */
  allowInsecureHttp?: boolean;
}

const DEFAULT_TIMEOUT_MS = 5000;
const HTTP_OK = 200;

/**
 * fetches and checks an issuer's OpenID provider configuration
 * @param issuer the configured issuer URL
 * @param options request options
 * @returns the issuer's JWKS endpoint and advertised algorithms
 * @throws {OidcError} OIDC_DISCOVERY_FAILED when the document cannot be fetched, is not JSON, names another issuer, or lacks an https jwks_uri (http only with allowInsecureHttp)
 */
export async function discoverIssuer(
  issuer: string,
  options?: DiscoverIssuerOptions,
): Promise<IssuerMetadata> {
  const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const document = await fetchDiscoveryDocument(url, timeoutMs);

  if (document.issuer !== issuer) {
    throw new OidcError(
      'OIDC_DISCOVERY_FAILED',
      `discovery document at ${url} names issuer "${String(document.issuer)}" instead of "${issuer}"`,
      { meta: { issuer, url } },
    );
  }

  const jwksProtocol =
    typeof document.jwks_uri === 'string'
      ? URL.parse(document.jwks_uri)?.protocol
      : undefined;
  const acceptedProtocols = options?.allowInsecureHttp
    ? ['https:', 'http:']
    : ['https:'];

  if (
    typeof document.jwks_uri !== 'string' ||
    !acceptedProtocols.includes(jwksProtocol ?? '')
  ) {
    throw new OidcError(
      'OIDC_DISCOVERY_FAILED',
      `discovery document at ${url} has no valid ${acceptedProtocols.length > 1 ? 'http(s)' : 'https'} jwks_uri`,
      { meta: { issuer, url } },
    );
  }

  const advertised = document.id_token_signing_alg_values_supported;
  const algorithms = Array.isArray(advertised)
    ? advertised.filter((value): value is string => typeof value === 'string')
    : undefined;

  return { jwksUri: document.jwks_uri, algorithms };
}

/**
 * fetches a discovery document without following redirects
 * @param url the well-known configuration address
 * @param timeoutMs request timeout in milliseconds
 * @returns the parsed JSON object
 * @throws {OidcError} OIDC_DISCOVERY_FAILED when the request fails, does not answer 200 or is not a JSON object
 */
async function fetchDiscoveryDocument(
  url: string,
  timeoutMs: number,
): Promise<Record<string, unknown>> {
  const response = await fetch(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
    headers: { accept: 'application/json' },
  }).catch((exception: unknown) => {
    throw new OidcError(
      'OIDC_DISCOVERY_FAILED',
      `discovery at ${url} failed: ${(exception as Error).message}`,
      { cause: exception, meta: { url } },
    );
  });

  if (response.status !== HTTP_OK) {
    throw new OidcError(
      'OIDC_DISCOVERY_FAILED',
      `discovery at ${url} answered ${response.status} instead of 200`,
      { meta: { url, status: response.status } },
    );
  }

  const document: unknown = await response.json().catch(() => null);

  if (typeof document !== 'object' || document === null) {
    throw new OidcError(
      'OIDC_DISCOVERY_FAILED',
      `discovery at ${url} did not return a JSON object`,
      { meta: { url } },
    );
  }

  return document as Record<string, unknown>;
}
