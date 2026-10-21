/**
 * Phase D Task 16 — fetchStatusListCredential freshness + failover semantics.
 *
 * Covered:
 *   1. fresh cache hit returns without HTTP
 *   2. expired-but-stale-acceptable returns "stale" on network error
 *   3. beyond stale TTL + unreachable returns "unreachable"
 *   4. successful refetch writes new entry (etag preserved)
 *   5. 304 conditional refetch — body preserved, fresh_until refreshed
 *   6. non-2xx response falls into the same failure branch as a network error
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { fetchStatusListCredential } from "../../src/status/fetch.ts";
import { InMemoryStatusCache } from "../../src/status/cache.ts";

test("fresh hit returns from cache without HTTP", async () => {
  const cache = new InMemoryStatusCache();
  await cache.set("https://x", {
    fetched_at: Date.now(),
    fresh_until: Date.now() + 60_000,
    body: { hello: 1 },
    etag: "v1",
  });
  let httpCalls = 0;
  const r = await fetchStatusListCredential("https://x", {
    cache,
    freshTtlSec: 3600,
    staleTtlSec: 86400,
    _testFetch: async () => {
      httpCalls++;
      return new Response("{}", { status: 200 });
    },
  });
  assert.equal(r.state, "fresh");
  assert.equal(httpCalls, 0);
});

test("expired but stale-acceptable returns 'stale'", async () => {
  const cache = new InMemoryStatusCache();
  const oldFetched = Date.now() - 7200_000;
  await cache.set("https://x", {
    fetched_at: oldFetched,
    fresh_until: oldFetched + 3600_000,
    body: { stale: true },
    etag: "v1",
  });
  const r = await fetchStatusListCredential("https://x", {
    cache,
    freshTtlSec: 3600,
    staleTtlSec: 86400,
    _testFetch: async () => {
      throw new Error("net");
    },
  });
  assert.equal(r.state, "stale");
  assert.ok(r.state === "stale" && r.entry.body !== undefined);
  assert.ok(r.state === "stale" && r.cached_age_sec >= 3600);
});

test(">24h since fetch + unreachable returns 'unreachable'", async () => {
  const cache = new InMemoryStatusCache();
  await cache.set("https://x", {
    fetched_at: Date.now() - 100_000_000,
    fresh_until: Date.now() - 90_000_000,
    body: {},
    etag: "v1",
  });
  const r = await fetchStatusListCredential("https://x", {
    cache,
    freshTtlSec: 3600,
    staleTtlSec: 86400,
    _testFetch: async () => {
      throw new Error("net");
    },
  });
  assert.equal(r.state, "unreachable");
});

test("successful refetch updates cache with new freshness", async () => {
  const cache = new InMemoryStatusCache();
  const r = await fetchStatusListCredential("https://x", {
    cache,
    freshTtlSec: 3600,
    staleTtlSec: 86400,
    _testFetch: async () =>
      new Response('{"hello":"world"}', {
        status: 200,
        headers: { etag: "abc" },
      }),
  });
  assert.equal(r.state, "fresh");
  const cached = await cache.get("https://x");
  assert.equal(cached?.etag, "abc");
});

test("304 conditional refetch preserves body, refreshes fresh_until, preserves etag", async () => {
  const cache = new InMemoryStatusCache();
  const oldFetched = Date.now() - 7200_000;
  const cachedBody = { revoked_indices: [42] };
  await cache.set("https://x", {
    fetched_at: oldFetched,
    fresh_until: oldFetched + 3600_000, // expired but stale-acceptable
    body: cachedBody,
    etag: "etag-v1",
  });

  let sawIfNoneMatch: string | null = null;
  const r = await fetchStatusListCredential("https://x", {
    cache,
    freshTtlSec: 3600,
    staleTtlSec: 86400,
    _testFetch: async (_url: string | URL | Request, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      sawIfNoneMatch = headers.get("if-none-match");
      return new Response(null, { status: 304 });
    },
  });

  assert.equal(sawIfNoneMatch, "etag-v1");
  assert.equal(r.state, "fresh");
  // Discriminant guard for narrowing.
  if (r.state !== "fresh") return;
  // Body preserved from cache.
  assert.deepEqual(r.entry.body, cachedBody);
  // Etag preserved.
  assert.equal(r.entry.etag, "etag-v1");
  // fresh_until refreshed forward.
  assert.ok(r.entry.fresh_until > oldFetched + 3600_000);
  // Cache was rewritten with refreshed timestamps.
  const recached = await cache.get("https://x");
  assert.ok(recached);
  assert.ok(recached!.fetched_at > oldFetched);
});

test("non-2xx response is treated as failure — falls back to stale when cache is stale-acceptable", async () => {
  const cache = new InMemoryStatusCache();
  const oldFetched = Date.now() - 7200_000;
  await cache.set("https://x", {
    fetched_at: oldFetched,
    fresh_until: oldFetched + 3600_000,
    body: { v: "cached" },
    etag: "v1",
  });
  const r = await fetchStatusListCredential("https://x", {
    cache,
    freshTtlSec: 3600,
    staleTtlSec: 86400,
    _testFetch: async () => new Response("boom", { status: 500 }),
  });
  assert.equal(r.state, "stale");
});

test("non-2xx response with no cache returns 'unreachable'", async () => {
  const cache = new InMemoryStatusCache();
  const r = await fetchStatusListCredential("https://x", {
    cache,
    freshTtlSec: 3600,
    staleTtlSec: 86400,
    _testFetch: async () => new Response("boom", { status: 500 }),
  });
  assert.equal(r.state, "unreachable");
});
