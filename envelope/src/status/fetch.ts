/**
 * fetchStatusListCredential — Status List 2021 Credential fetcher.
 *
 * Phase D Task 16. Verifier-side I/O helper. Three observable outcomes:
 *
 *   - "fresh"        — cache hit within freshTtl OR successful refetch (200/304).
 *   - "stale"        — refetch failed but cache is within fresh_until + staleTtl;
 *                      caller MAY use entry.body and SHOULD surface cached_age_sec.
 *   - "unreachable"  — refetch failed and cache is missing or beyond stale TTL;
 *                      caller MUST treat the status check as unavailable.
 *
 * Conditional revalidation: if a cache entry has an etag, the fetcher sends
 * `if-none-match`; a 304 response preserves the cached body and etag, refreshing
 * only `fetched_at` / `fresh_until`.
 *
 * Failure mode: ALL failures (network throw, non-2xx response, JSON parse error)
 * funnel into the same catch branch — the function never throws to the caller.
 *
 * The `_testFetch` option is the seam for tests; production callers omit it and
 * the global `fetch` is used. Deferred to a later task: AbortSignal timeout +
 * retry/backoff (plan §Task 16 marks both as hardening follow-ups).
 */

import type {
  StatusCacheStorage,
  StatusFetchResult,
  StatusListEntry,
} from "./types.ts";

export interface FetchOpts {
  cache: StatusCacheStorage;
  freshTtlSec: number;
  staleTtlSec: number;
  _testFetch?: typeof fetch;
}

export async function fetchStatusListCredential(
  url: string,
  opts: FetchOpts,
): Promise<StatusFetchResult> {
  const f = opts._testFetch ?? fetch;
  const now = Date.now();
  const cached = await opts.cache.get(url);

  // Fresh cache hit — no HTTP.
  if (cached && cached.fresh_until > now) {
    return { state: "fresh", entry: cached };
  }

  try {
    const headers: Record<string, string> = {};
    if (cached?.etag) headers["if-none-match"] = cached.etag;
    const res = await f(url, { headers });

    // 304 — server confirms cached body is still current.
    if (res.status === 304 && cached) {
      // exactOptionalPropertyTypes: spread cached (which may or may not carry etag),
      // then overlay the refreshed timestamps. Etag is preserved as-is.
      const refreshed: StatusListEntry = {
        ...cached,
        fetched_at: now,
        fresh_until: now + opts.freshTtlSec * 1000,
      };
      await opts.cache.set(url, refreshed);
      return { state: "fresh", entry: refreshed };
    }

    if (!res.ok) throw new Error(`http_${res.status}`);

    const body: unknown = await res.json();
    const etag = res.headers.get("etag");
    // Split branches keep `etag?: string` from receiving `undefined` under
    // exactOptionalPropertyTypes (same discipline as envelope/src/tsa/attach.ts).
    const entry: StatusListEntry =
      etag !== null
        ? {
            fetched_at: now,
            fresh_until: now + opts.freshTtlSec * 1000,
            body,
            etag,
          }
        : {
            fetched_at: now,
            fresh_until: now + opts.freshTtlSec * 1000,
            body,
          };
    await opts.cache.set(url, entry);
    return { state: "fresh", entry };
  } catch (err) {
    if (cached) {
      const staleUntil = cached.fresh_until + opts.staleTtlSec * 1000;
      if (now < staleUntil) {
        return {
          state: "stale",
          entry: cached,
          cached_age_sec: Math.floor((now - cached.fetched_at) / 1000),
        };
      }
    }
    const reason = err instanceof Error ? err.message : String(err);
    return { state: "unreachable", reason };
  }
}
