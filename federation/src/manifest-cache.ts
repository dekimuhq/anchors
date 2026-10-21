/**
 * ManifestCache — TTL + LRU cache for parsed issuer manifests.
 *
 * Sibling pattern to `InMemoryKeyCache` in `@dekimuhq/did-web-resolver`.
 * Keyed by issuer DID (`did:web:<domain>`). Used by `fetchIssuerManifest`
 * and `verifyIssuerManifest` to avoid re-fetching and re-verifying
 * manifests within the TTL window.
 */

import type { IssuerManifestV1 } from "./types.ts";

export interface ManifestCacheOptions {
  /** Maximum number of cached manifests. Default: 128. */
  maxEntries?: number;
  /** TTL for successful entries in milliseconds. Default: 5 min. */
  ttlMs?: number;
  /** TTL for negative entries (fetch/verify failures). Default: 30 s. */
  negativeTtlMs?: number;
}

interface CacheEntry {
  manifest: IssuerManifestV1 | null;
  setAt: number;
  negative: boolean;
}

export class ManifestCache {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly negativeTtlMs: number;

  constructor(opts: ManifestCacheOptions = {}) {
    this.maxEntries = opts.maxEntries ?? 128;
    this.ttlMs = opts.ttlMs ?? 5 * 60_000;
    this.negativeTtlMs = opts.negativeTtlMs ?? 30_000;
  }

  get(iss: string, now: number = Date.now()): IssuerManifestV1 | null | undefined {
    const entry = this.cache.get(iss);
    if (!entry) return undefined; // miss

    const ttl = entry.negative ? this.negativeTtlMs : this.ttlMs;
    if (now - entry.setAt >= ttl) {
      this.cache.delete(iss);
      return undefined; // expired
    }

    return entry.manifest; // hit (null for negative cache)
  }

  set(iss: string, manifest: IssuerManifestV1 | null, now: number = Date.now()): void {
    // Evict oldest if at capacity (FIFO by insertion order)
    if (this.cache.size >= this.maxEntries && !this.cache.has(iss)) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }

    this.cache.set(iss, {
      manifest,
      setAt: now,
      negative: manifest === null,
    });
  }

  delete(iss: string): boolean {
    return this.cache.delete(iss);
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }
}
