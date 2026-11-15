import { OidcError } from '#errors';

import type { IssuerConfig } from '#types';

// every key an `issuers[]` entry may carry; typing it as a record of IssuerConfig keeps the two in step
const ISSUER_KEYS: Record<keyof IssuerConfig, true> = {
  id: true,
  issuer: true,
  audience: true,
  algorithms: true,
  jwksUri: true,
  allowInsecureHttp: true,
  usernameTemplate: true,
  groupTemplates: true,
  matchClaim: true,
  matchCaseInsensitive: true,
  allow: true,
};

// how many edits an unknown key may be from a known key for it to be suggested
const MAX_SUGGESTION_DISTANCE = 2;

/**
 * refuses any key an issuer entry does not define, so a misspelled option cannot silently fall back to its looser default
 * @param record the `issuers[]` entry as written in config
 * @param issuerId the issuer named in errors
 * @throws {OidcError} OIDC_CONFIG_INVALID naming the issuer and the unknown key, suggesting the key it most resembles
 */
export function rejectUnknownIssuerKeys(
  record: Record<string, unknown>,
  issuerId: string,
): void {
  const unknownKey = Object.keys(record).find(
    (key) => !Object.hasOwn(ISSUER_KEYS, key),
  );

  if (unknownKey === undefined) {
    return;
  }

  const suggestion = suggestKey(unknownKey, Object.keys(ISSUER_KEYS));
  const hint =
    suggestion === undefined ? '' : `; did you mean "${suggestion}"?`;
  throw new OidcError(
    'OIDC_CONFIG_INVALID',
    `issuer "${issuerId}" has an unknown key "${unknownKey}"${hint}`,
    { meta: { issuerId, field: unknownKey } },
  );
}

/**
 * finds the known key an unknown key was most likely meant to be, ignoring case, `_` and `-`
 * @param key the unknown key
 * @param candidates the known keys
 * @returns the closest known key within a couple of edits, or undefined when none is close
 */
export function suggestKey(
  key: string,
  candidates: string[],
): string | undefined {
  const normalizedKey = normalizeKey(key);

  return candidates
    .map((candidate) => ({
      candidate,
      distance: measureEditDistance(normalizedKey, normalizeKey(candidate)),
    }))
    .filter(({ distance }) => distance <= MAX_SUGGESTION_DISTANCE)
    .sort((left, right) => left.distance - right.distance)[0]?.candidate;
}

/**
 * counts the single-character insertions, deletions and substitutions that turn one text into another
 * @param from the text to start from
 * @param to the text to reach
 * @returns the Levenshtein distance
 */
export function measureEditDistance(from: string, to: string): number {
  const firstRow = Array.from({ length: to.length + 1 }, (_, index) => index);

  const lastRow = [...from].reduce(
    (previousRow, fromCharacter, fromIndex) =>
      [...to].reduce(
        (row, toCharacter, toIndex) => [
          ...row,
          Math.min(
            previousRow[toIndex + 1]! + 1,
            row[toIndex]! + 1,
            previousRow[toIndex]! + (fromCharacter === toCharacter ? 0 : 1),
          ),
        ],
        [fromIndex + 1],
      ),
    firstRow,
  );

  return lastRow[to.length]!;
}

/**
 * folds a key to lower case without `_` or `-`, so `jwks_uri` and `jwksUri` compare equal
 * @param key the key as written
 * @returns the folded key
 */
function normalizeKey(key: string): string {
  return key.toLowerCase().replaceAll(/[_-]/g, '');
}
