import { describe, expect, it } from 'vitest';

import { compilePattern, matchesAllowEntries } from '#pattern';

describe('fn:matchesAllowEntries', () => {
  it('should admit claims when every condition of an entry matches', () => {
    const entries = [
      [
        { claim: 'repository', patterns: [compilePattern('acme/service-*')] },
        { claim: 'sub', patterns: [compilePattern('repo:acme/**')] },
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
      [{ claim: 'repository', patterns: [compilePattern('acme/app')] }],
      [
        {
          claim: 'repository',
          patterns: [compilePattern('beta/one'), compilePattern('beta/two')],
        },
      ],
    ];

    const result = matchesAllowEntries(entries, { repository: 'beta/two' });

    expect(result).toBe(true);
  });

  it('should match number and boolean claims as text', () => {
    const entries = [
      [
        { claim: 'repository_id', patterns: [compilePattern('42')] },
        { claim: 'is_protected', patterns: [compilePattern('true')] },
      ],
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
    const entries = [
      [{ claim: 'repository', patterns: [compilePattern('**')] }],
    ];

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
