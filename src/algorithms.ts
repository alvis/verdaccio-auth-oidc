/** the asymmetric signature algorithms ever accepted, whatever config or discovery says */
export const SAFE_ALGORITHMS: readonly string[] = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
  'Ed25519',
];

/** inputs for {@link resolveAlgorithms} */
export interface ResolveAlgorithmsParams {
  /** algorithms listed in the issuer config, already checked against the safe set */
  configured?: string[];
  /** `id_token_signing_alg_values_supported` from discovery */
  discovered?: string[];
}

/**
 * checks whether an algorithm is in the safe asymmetric set
 * @param algorithm a JWS algorithm name
 * @returns true for an RS, PS, ES or EdDSA algorithm
 */
export function isSafeAlgorithm(algorithm: string): boolean {
  return SAFE_ALGORITHMS.includes(algorithm);
}

/**
 * resolves the algorithms a token may use: configured first, then discovered, then the safe set, always capped to the safe set
 * @param params configured and discovered algorithms
 * @returns the accepted algorithms, empty when discovery offers no safe algorithm
 */
export function resolveAlgorithms(params: ResolveAlgorithmsParams): string[] {
  const { configured, discovered } = params;
  const candidates = configured ?? discovered ?? SAFE_ALGORITHMS;

  return candidates.filter(isSafeAlgorithm);
}
