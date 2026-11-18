import { describe, expect, it } from 'vitest';

import { IdentityCache } from '#cache';

import type { Identity } from '#types';

const NOW_MS = 1_000_000;

const identity: Identity = {
  issuerId: 'gha',
  name: 'gha:acme/app',
  groups: ['gha-org:acme'],
};

/**
 * builds an identity for a distinct repository
 * @param repository the repository the identity names
 * @returns an identity named after the repository, with no groups
 */
function createIdentity(repository: string): Identity {
  return { issuerId: 'gha', name: `gha:${repository}`, groups: [] };
}

describe('cl:IdentityCache', () => {
  describe('mt:get', () => {
    it('should return a copy of a cached identity before it expires', () => {
      const cache = new IdentityCache({
        ttlSeconds: 300,
        maxEntries: 10,
        readNowMs: () => NOW_MS,
      });
      cache.set('token', identity, 2000);

      const result = cache.get('token');

      expect(result).toEqual(identity);
      expect(result).not.toBe(identity);
    });

    it('should keep a cached identity apart from later changes to the stored one', () => {
      const cache = new IdentityCache({
        ttlSeconds: 300,
        maxEntries: 10,
        readNowMs: () => NOW_MS,
      });
      const stored = createIdentity('acme/app');
      cache.set('token', stored, 2000);
      stored.groups.push('admin');

      const result = cache.get('token');

      expect(result).toEqual(createIdentity('acme/app'));
    });

    it('should miss a token it never cached', () => {
      const cache = new IdentityCache({
        ttlSeconds: 300,
        maxEntries: 10,
        readNowMs: () => NOW_MS,
      });
      cache.set('token', identity, 2000);

      const result = cache.get('another-token');

      expect(result).toBeUndefined();
    });

    it.each([
      {
        case: 'at ttl when the token outlives it',
        expiresAtSeconds: 2000,
        hitAtMs: NOW_MS + 299_999,
        missAtMs: NOW_MS + 300_000,
      },
      {
        case: 'at the token exp when it comes before ttl',
        expiresAtSeconds: 1100,
        hitAtMs: 1_099_999,
        missAtMs: 1_100_000,
      },
    ])('should miss $case', ({ expiresAtSeconds, hitAtMs, missAtMs }) => {
      const clock = { nowMs: NOW_MS };
      const cache = new IdentityCache({
        ttlSeconds: 300,
        maxEntries: 10,
        readNowMs: () => clock.nowMs,
      });
      cache.set('token', identity, expiresAtSeconds);

      clock.nowMs = hitAtMs;
      const hit = cache.get('token');
      clock.nowMs = missAtMs;
      const miss = cache.get('token');

      expect({ hit, miss }).toEqual({ hit: identity, miss: undefined });
    });

    it('should evict the least recently used entry at maxEntries', () => {
      const cache = new IdentityCache({
        ttlSeconds: 300,
        maxEntries: 2,
        readNowMs: () => NOW_MS,
      });
      cache.set('first', createIdentity('acme/first'), 2000);
      cache.set('second', createIdentity('acme/second'), 2000);
      cache.get('first');
      cache.set('third', createIdentity('acme/third'), 2000);

      const result = ['first', 'second', 'third'].map((token) =>
        cache.get(token),
      );

      expect(result).toEqual([
        createIdentity('acme/first'),
        undefined,
        createIdentity('acme/third'),
      ]);
    });

    it('should replace the identity cached for a token stored again', () => {
      const cache = new IdentityCache({
        ttlSeconds: 300,
        maxEntries: 1,
        readNowMs: () => NOW_MS,
      });
      cache.set('token', createIdentity('acme/old'), 2000);
      cache.set('token', createIdentity('acme/new'), 2000);

      const result = cache.get('token');

      expect(result).toEqual(createIdentity('acme/new'));
    });

    it.each([
      { case: 'ttl is 0', ttlSeconds: 0, maxEntries: 10 },
      { case: 'maxEntries is 0', ttlSeconds: 300, maxEntries: 0 },
    ])('should cache nothing when $case', ({ ttlSeconds, maxEntries }) => {
      const cache = new IdentityCache({
        ttlSeconds,
        maxEntries,
        readNowMs: () => NOW_MS,
      });
      cache.set('token', identity, 2000);

      const result = cache.get('token');

      expect(result).toBeUndefined();
    });
  });
});
