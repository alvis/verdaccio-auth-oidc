import { createHash } from 'node:crypto';

import type { Identity } from '#types';

const MS_PER_SECOND = 1000;

/** construction parameters for {@link IdentityCache} */
export interface IdentityCacheParams {
  /** how long, in seconds, an identity stays cached; 0 disables the cache */
  ttlSeconds: number;
  /** the maximum number of cached identities; 0 disables the cache */
  maxEntries: number;
  /** the clock, in epoch milliseconds */
  readNowMs?: () => number;
}

interface CacheEntry {
  identity: Identity;
  expiresAtMs: number;
}

/** an LRU cache of verified identities keyed by a SHA-512 hash of the token, never the token itself */
export class IdentityCache {
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #readNowMs: () => number;
  readonly #entriesByKey = new Map<string, CacheEntry>();

  /**
   * creates an identity cache
   * @param params cache limits and clock
   */
  constructor(params: IdentityCacheParams) {
    const { ttlSeconds, maxEntries, readNowMs = Date.now } = params;

    this.#ttlMs = ttlSeconds * MS_PER_SECOND;
    this.#maxEntries = maxEntries;
    this.#readNowMs = readNowMs;
  }

  /**
   * looks up the identity cached for a token
   * @param token the raw bearer token
   * @returns a copy of the identity, or undefined on a miss or expiry
   */
  public get(token: string): Identity | undefined {
    const key = hashToken(token);
    const entry = this.#entriesByKey.get(key);

    if (!entry) {
      return undefined;
    }

    this.#entriesByKey.delete(key);

    if (entry.expiresAtMs <= this.#readNowMs()) {
      return undefined;
    }

    // re-insert to mark the entry as most recently used
    this.#entriesByKey.set(key, entry);

    return structuredClone(entry.identity);
  }

  /**
   * caches an identity until `min(now + ttl, exp)`, skipping one that has already expired
   * @param token the raw bearer token
   * @param identity the verified identity
   * @param expiresAtSeconds the token's exp claim, in epoch seconds
   */
  public set(
    token: string,
    identity: Identity,
    expiresAtSeconds: number,
  ): void {
    if (this.#ttlMs === 0 || this.#maxEntries === 0) {
      return;
    }

    const nowMs = this.#readNowMs();
    const expiresAtMs = Math.min(
      nowMs + this.#ttlMs,
      expiresAtSeconds * MS_PER_SECOND,
    );

    // an entry that is already expired could never be served, only evict a live one
    if (expiresAtMs <= nowMs) {
      return;
    }

    const key = hashToken(token);
    this.#entriesByKey.delete(key);
    this.#entriesByKey.set(key, {
      identity: structuredClone(identity),
      expiresAtMs,
    });

    // evict the least recently used entries, which lead the insertion order
    for (const oldestKey of this.#entriesByKey.keys()) {
      if (this.#entriesByKey.size <= this.#maxEntries) {
        break;
      }

      this.#entriesByKey.delete(oldestKey);
    }
  }
}

/**
 * hashes a token for use as a cache key
 * @param token the raw bearer token
 * @returns the hex SHA-512 digest
 */
function hashToken(token: string): string {
  return createHash('sha512').update(token).digest('hex');
}
