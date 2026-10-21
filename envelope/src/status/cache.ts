/**
 * InMemoryStatusCache — bounded LRU cache for Status List 2021 Credentials.
 *
 * Phase D Task 16. Default backend behind `fetchStatusListCredential`; callers
 * needing process-wide or cross-host persistence implement `StatusCacheStorage`
 * with their own store (Redis, filesystem, etc.) and pass it via FetchOpts.
 *
 * LRU semantics: `Map` preserves insertion order; touching (`get`) or replacing
 * (`set`) an existing key deletes-then-re-inserts so the touched entry becomes
 * most-recently-used. When size exceeds `maxEntries`, the oldest key (head of
 * the iteration order) is evicted.
 */

import type { StatusCacheStorage, StatusListEntry } from "./types.ts";

export class InMemoryStatusCache implements StatusCacheStorage {
  private readonly map = new Map<string, StatusListEntry>();
  private readonly maxEntries: number;

  constructor(maxEntries: number = 256) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new Error(
        `InMemoryStatusCache: maxEntries must be a positive integer, got ${maxEntries}`,
      );
    }
    this.maxEntries = maxEntries;
  }

  async get(url: string): Promise<StatusListEntry | undefined> {
    const v = this.map.get(url);
    if (v) {
      this.map.delete(url);
      this.map.set(url, v);
    }
    return v;
  }

  async set(url: string, entry: StatusListEntry): Promise<void> {
    if (this.map.has(url)) this.map.delete(url);
    this.map.set(url, entry);
    while (this.map.size > this.maxEntries) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
  }
}
