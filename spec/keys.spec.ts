import { describe, expect, it } from 'vitest';

import { measureEditDistance, suggestKey } from '#keys';

describe('fn:suggestKey', () => {
  it.each([
    { key: 'jwks_uri', expected: 'jwksUri' },
    { key: 'Audience', expected: 'audience' },
    { key: 'algorithm', expected: 'algorithms' },
    { key: 'issuerr', expected: 'issuer' },
  ])('should suggest $expected for $key', ({ key, expected }) => {
    const result = suggestKey(key, [
      'issuer',
      'issuers',
      'jwksUri',
      'audience',
      'algorithms',
    ]);

    expect(result).toBe(expected);
  });

  it('should suggest nothing when no key is within two edits', () => {
    const result = suggestKey('environment', ['issuer', 'jwksUri']);

    expect(result).toBeUndefined();
  });
});

describe('fn:measureEditDistance', () => {
  it.each([
    { from: '', to: '', expected: 0 },
    { from: 'abc', to: '', expected: 3 },
    { from: '', to: 'abc', expected: 3 },
    { from: 'kitten', to: 'sitting', expected: 3 },
    { from: 'algorithm', to: 'algorithms', expected: 1 },
  ])(
    'should count $expected edits from "$from" to "$to"',
    ({ from, to, expected }) => {
      const result = measureEditDistance(from, to);

      expect(result).toBe(expected);
    },
  );
});
