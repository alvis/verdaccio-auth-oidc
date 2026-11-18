import type { AllowEntry, Claims } from '#types';

/** options for {@link compilePattern} */
export interface CompilePatternOptions {
  /** whether matching ignores case */
  isCaseInsensitive?: boolean;
}

// `**` must be tried before `*`, so the alternation lists it first
const tokenRegex = /\*\*|\*|[^*]+/g;
const regexSpecialCharacterRegex = /[.*+?^${}()|[\]\\]/g;

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
