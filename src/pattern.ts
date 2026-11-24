import type { AllowEntry, Claims, ResolvedPluginConfig } from '#types';

/** an allow entry whose matchClaim pattern has a wildcard in its owner part, before its first `/`, so it trusts owners the config does not control, reported at startup */
export interface WildcardTrustScope {
  /** the issuer the allow entry belongs to */
  issuerId: string;
  /** the entry's position in the issuer's allow list */
  entryIndex: number;
  /** the issuer's matchClaim */
  claim: string;
  /** the pattern as written in config */
  pattern: string;
}

/** options for {@link compilePattern} */
export interface CompilePatternOptions {
  /** whether matching ignores case */
  isCaseInsensitive?: boolean;
}

// `**` must be tried before `*`, so the alternation lists it first
const tokenRegex = /\*\*|\*|[^*]+/g;
const regexSpecialCharacterRegex = /[.*+?^${}()|[\]\\]/g;
// a `*` before any `/`, which also catches `**` and a pattern with no `/` at all
const ownerWildcardRegex = /^[^/]*\*/;

/**
 * compiles an allow pattern, where `*` spans any run without `/` or `:` and `**` spans anything
 * @param pattern the pattern as written in config
 * @param options matching options
 * @returns an anchored regular expression
 */
export function compilePattern(
  pattern: string,
  options?: CompilePatternOptions,
): RegExp {
  const body = [...pattern.matchAll(tokenRegex)]
    .map(([token]) => {
      switch (token) {
        case '**':
          return '.*';
        case '*':
          return '[^/:]*';
        default:
          return token.replace(regexSpecialCharacterRegex, String.raw`\$&`);
      }
    })
    .join('');

  return new RegExp(`^${body}$`, options?.isCaseInsensitive ? 'iu' : 'u');
}

/**
 * lists the allow entries whose matchClaim pattern has a wildcard in its owner part, the text before its first `/`, such as `*`, `**` or `acme-*`; in a `repo:<owner>/<repo>` sub claim that text holds the owner too
 * @param config the resolved plugin config
 * @returns every matchClaim pattern that leaves an issuer's trust scope open to owners the config does not control
 */
export function listWildcardTrustScopes(
  config: ResolvedPluginConfig,
): WildcardTrustScope[] {
  return config.issuers.flatMap(({ id: issuerId, matchClaim, allow }) =>
    allow.flatMap((conditions, entryIndex) =>
      conditions
        .filter(({ claim }) => claim === matchClaim)
        .flatMap(({ sources }) => sources)
        .filter((pattern) => ownerWildcardRegex.test(pattern))
        .map((pattern) => ({
          issuerId,
          entryIndex,
          claim: matchClaim,
          pattern,
        })),
    ),
  );
}

/**
 * checks verified claims against allow entries
 * @param entries compiled allow entries
 * @param claims verified token claims
 * @returns true when any entry has every one of its claim conditions matched
 */
export function matchesAllowEntries(
  entries: AllowEntry[],
  claims: Claims,
): boolean {
  return entries.some((conditions) =>
    conditions.every(({ claim, patterns }) => {
      const value = claims[claim];
      const text =
        typeof value === 'string' ||
        typeof value === 'number' ||
        typeof value === 'boolean'
          ? String(value)
          : undefined;

      return (
        text !== undefined && patterns.some((pattern) => pattern.test(text))
      );
    }),
  );
}
