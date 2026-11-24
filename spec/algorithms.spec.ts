import { describe, expect, it } from 'vitest';

import { resolveAlgorithms } from '#algorithms';

describe('fn:resolveAlgorithms', () => {
  it('should cap discovered algorithms to the safe asymmetric set', () => {
    const result = resolveAlgorithms({
      discovered: ['RS256', 'HS256', 'none'],
    });

    expect(result).toEqual(['RS256']);
  });

  it('should fall back to the safe set when neither config nor discovery names an algorithm', () => {
    const result = resolveAlgorithms({});

    expect(result).toEqual([
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
    ]);
  });

  it('should prefer a configured list over discovery and drop HS* and none from it', () => {
    const result = resolveAlgorithms({
      configured: ['ES256', 'HS256', 'none'],
      discovered: ['RS256'],
    });

    expect(result).toEqual(['ES256']);
  });
});
