import { describe, expect, it } from 'vitest';

import { parseConfig } from '#config';
import {
  compilePattern,
  listWildcardTrustScopes,
  matchesAllowEntries,
} from '#pattern';

import type { ClaimCondition } from '#types';

/**
 * compiles one allow condition as config parsing would
 * @param claim the claim the condition reads
 * @param sources the patterns as written in config
 * @returns the compiled condition
 */
function condition(claim: string, ...sources: string[]): ClaimCondition {
  return {
    claim,
    patterns: sources.map((source) => compilePattern(source)),
    sources,
  };
}

describe('fn:matchesAllowEntries', () => {
  it('should admit claims when every condition of an entry matches', () => {
    const entries = [
      [
        condition('repository', 'acme/service-*'),
        condition('sub', 'repo:acme/**'),
      ],
    ];

    const result = matchesAllowEntries(entries, {
      repository: 'acme/service-a',
      sub: 'repo:acme/service-a:environment:npmjs',
    });

    expect(result).toBe(true);
  });

  it('should admit claims when any entry matches and any pattern of a condition matches', () => {
    const entries = [
      [condition('repository', 'acme/app')],
      [condition('repository', 'beta/one', 'beta/two')],
    ];

    const result = matchesAllowEntries(entries, { repository: 'beta/two' });

    expect(result).toBe(true);
  });

  it('should match number and boolean claims as text', () => {
    const entries = [
      [condition('repository_id', '42'), condition('is_protected', 'true')],
    ];

    const result = matchesAllowEntries(entries, {
      repository_id: 42,
      is_protected: true,
    });

    expect(result).toBe(true);
  });

  it.each([
    { case: 'a missing claim', claims: {} },
    { case: 'an object claim', claims: { repository: { name: 'acme/app' } } },
    { case: 'a list claim', claims: { repository: ['acme/app'] } },
  ])('should reject $case', ({ claims }) => {
    const entries = [[condition('repository', '**')]];

    const result = matchesAllowEntries(entries, claims);

    expect(result).toBe(false);
  });
});

describe('fn:compilePattern', () => {
  it.each([
    { pattern: 'acme/*', value: 'acme/app', expected: true },
    { pattern: 'acme/*', value: 'acme/app/sub', expected: false },
    { pattern: 'repo:*', value: 'repo:acme:ref', expected: false },
    {
      pattern: 'repo:acme/**',
      value: 'repo:acme/app:ref:main',
      expected: true,
    },
    { pattern: 'acme/*', value: 'other/acme/app', expected: false },
    { pattern: 'acme/app.js', value: 'acme/appXjs', expected: false },
    { pattern: 'acme/(app)+', value: 'acme/(app)+', expected: true },
  ])(
    'should test $value against $pattern as $expected',
    ({ pattern, value, expected }) => {
      const regex = compilePattern(pattern);

      const result = regex.test(value);

      expect(result).toBe(expected);
    },
  );

  it.each([
    { isCaseInsensitive: true, expected: [true, true] },
    { isCaseInsensitive: false, expected: [false, false] },
  ])(
    'should match across case only when isCaseInsensitive is $isCaseInsensitive',
    ({ isCaseInsensitive, expected }) => {
      const regex = compilePattern('Acme/*', { isCaseInsensitive });

      const result = [regex.test('acme/app'), regex.test('ACME/APP')];

      expect(result).toEqual(expected);
    },
  );
});

describe('fn:listWildcardTrustScopes', () => {
  const githubIssuer = {
    id: 'gha',
    issuer: 'https://token.actions.githubusercontent.com',
    audience: 'https://registry.example.com',
    usernameTemplate: 'gha:{repository}',
    groupTemplates: ['gha-org:{repository_owner}'],
    matchClaim: 'repository',
  };

  it('should list every matchClaim pattern with a wildcard before its first slash, naming the issuer and entry', () => {
    const config = parseConfig({
      issuers: [
        {
          ...githubIssuer,
          allow: [
            { repository: 'acme/*' },
            { repository: ['acme/app', '*/*'], ref: '*' },
            { repository: ['**', 'acme-*/*'] },
          ],
        },
        {
          ...githubIssuer,
          id: 'gitlab',
          issuer: 'https://gitlab.com',
          matchClaim: 'namespace_path',
          allow: [{ namespace_path: '*' }],
        },
      ],
    });

    const result = listWildcardTrustScopes(config);

    expect(result).toEqual([
      { issuerId: 'gha', entryIndex: 1, claim: 'repository', pattern: '*/*' },
      { issuerId: 'gha', entryIndex: 2, claim: 'repository', pattern: '**' },
      {
        issuerId: 'gha',
        entryIndex: 2,
        claim: 'repository',
        pattern: 'acme-*/*',
      },
      {
        issuerId: 'gitlab',
        entryIndex: 0,
        claim: 'namespace_path',
        pattern: '*',
      },
    ]);
  });

  it.each([
    { matchClaim: 'repository', pattern: '*', expected: true },
    { matchClaim: 'repository', pattern: '**', expected: true },
    { matchClaim: 'repository', pattern: '*/*', expected: true },
    { matchClaim: 'repository_owner', pattern: 'acme-*', expected: true },
    { matchClaim: 'repository_owner', pattern: 'acme**', expected: true },
    { matchClaim: 'repository', pattern: 'acme-*/*', expected: true },
    {
      matchClaim: 'sub',
      pattern: 'repo:*/*:ref:refs/heads/main',
      expected: true,
    },
    { matchClaim: 'sub', pattern: 'repo:**', expected: true },
    { matchClaim: 'repository', pattern: 'acme/*', expected: false },
    { matchClaim: 'repository', pattern: 'acme/**', expected: false },
    { matchClaim: 'repository', pattern: 'acme/repo', expected: false },
    { matchClaim: 'repository_owner', pattern: 'acme', expected: false },
    {
      matchClaim: 'sub',
      pattern: 'repo:acme/*:ref:refs/heads/main',
      expected: false,
    },
  ])(
    'should flag $matchClaim pattern $pattern as $expected',
    ({ matchClaim, pattern, expected }) => {
      const config = parseConfig({
        issuers: [
          { ...githubIssuer, matchClaim, allow: [{ [matchClaim]: pattern }] },
        ],
      });

      const result = listWildcardTrustScopes(config).length > 0;

      expect(result).toBe(expected);
    },
  );

  it('should list nothing when every matchClaim pattern pins its owner before any wildcard', () => {
    const config = parseConfig({
      issuers: [
        {
          ...githubIssuer,
          allow: [{ repository: ['acme/*', 'acme/**'], ref: '**' }],
        },
      ],
    });

    const result = listWildcardTrustScopes(config);

    expect(result).toEqual([]);
  });
});
