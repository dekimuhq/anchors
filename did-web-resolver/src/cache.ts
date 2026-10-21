export interface KeyCache {
  get(key: string): string | undefined;
  set(key: string, value: string): void;
  clear(): void;
  /**
   * Optional negative-cache surface. Implementations MAY override to prevent
   * hot-loop fetches against a known-broken issuer while still letting them
   * recover within a bounded window. If undefined on a KeyCache, the resolver
   * skips negative caching entirely.
   *
   * Used by the resolver for `non_200` and `no_matching_key` outcomes (per
   * plan §1.5). Other failure codes are NOT negatively cached — fetch_failed
   * may be transient, window violations are stable but rare.
   */
  getNegative?(key: string): string | undefined;
  setNegative?(key: string, errorCode: string): void;
}

interface PositiveEntry {
  kind: "positive";
  value: string;
  setAt: number;
}

interface NegativeEntry {
  kind: "negative";
  errorCode: string;
  setAt: number;
}

type Entry = PositiveEntry | NegativeEntry;

export interface InMemoryKeyCacheOptions {
  maxEntries: number;
  ttlMs: number;
  /**
   * Negative-cache TTL. When set, the cache stores failure outcomes (via
   * setNegative) and returns them through getNegative for this many ms. 0 or
   * undefined disables negative caching. Default per plan §1.5: 30_000.
   */
  negativeTtlMs?: number;
  now?: () => number;
}

/**
 * Bounded LRU + TTL cache. `now` is injectable for tests; defaults to Date.now.
 * Eviction rule: when size > maxEntries after a `set`, drop the oldest by
 * Map insertion order (Map iteration is insertion order; `get` re-inserts).
 * Expiry rule: an entry is expired when `now() - setAt >= ttlMs`.
 *
 * Negative caching shares the same map and eviction window; negativeTtlMs
 * applies only to negative entries. Promoting a known-broken issuer to a
 * working one is automatic — once `setAt + negativeTtlMs <= now`, the cache
 * returns undefined and the resolver re-fetches.
 *
 * Cache-poisoning resistance: the cache key includes `iss_key`, so swapping
 * the public key requires a new cache key. A malicious "replace the public
 * key" attack cannot win against a cache hit on the legitimate key.
 */
export class InMemoryKeyCache implements KeyCache {
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly negativeTtlMs: number;
  private readonly nowFn: () => number;
  private readonly map = new Map<string, Entry>();

  constructor(opts: InMemoryKeyCacheOptions) {
    if (!Number.isInteger(opts.maxEntries) || opts.maxEntries <= 0) {
      throw new Error("InMemoryKeyCache: maxEntries must be a positive integer");
    }
    if (opts.negativeTtlMs !== undefined && opts.negativeTtlMs < 0) {
      throw new Error("InMemoryKeyCache: negativeTtlMs must be >= 0");
    }
    this.maxEntries = opts.maxEntries;
    this.ttlMs = opts.ttlMs;
    this.negativeTtlMs = opts.negativeTtlMs ?? 0;
    this.nowFn = opts.now ?? (() => Date.now());
  }

  get(key: string): string | undefined {
    const entry = this.map.get(key);
    if (entry === undefined) return undefined;
    if (entry.kind !== "positive") return undefined;
    if (this.nowFn() - entry.setAt >= this.ttlMs) {
      this.map.delete(key);
      return undefined;
    }
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.value;
  }

  set(key: string, value: string): void {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, { kind: "positive", value, setAt: this.nowFn() });
    this.evictOverflow();
  }

  getNegative(key: string): string | undefined {
    if (this.negativeTtlMs === 0) return undefined;
    const entry = this.map.get(key);
    if (entry === undefined) return undefined;
    if (entry.kind !== "negative") return undefined;
    if (this.nowFn() - entry.setAt >= this.negativeTtlMs) {
      this.map.delete(key);
      return undefined;
    }
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.errorCode;
  }

  setNegative(key: string, errorCode: string): void {
    if (this.negativeTtlMs === 0) return;
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, { kind: "negative", errorCode, setAt: this.nowFn() });
    this.evictOverflow();
  }

  clear(): void {
    this.map.clear();
  }

  private evictOverflow(): void {
    while (this.map.size > this.maxEntries) {
      const oldestKey = this.map.keys().next().value;
      if (oldestKey === undefined) break;
      this.map.delete(oldestKey);
    }
  }
}
