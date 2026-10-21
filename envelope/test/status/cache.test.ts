/**
 * Phase D Task 16 — InMemoryStatusCache LRU semantics.
 *
 * Three invariants:
 *   1. set() beyond maxEntries evicts the oldest (least-recently-used) key.
 *   2. get() bumps the touched key to MRU (so it survives the next eviction).
 *   3. set() on an existing key replaces (not duplicates) and bumps to MRU.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { InMemoryStatusCache } from "../../src/status/cache.ts";

test("LRU evicts oldest", async () => {
  const c = new InMemoryStatusCache(2);
  await c.set("a", { fetched_at: 1, fresh_until: 100, body: {} });
  await c.set("b", { fetched_at: 2, fresh_until: 100, body: {} });
  await c.set("c", { fetched_at: 3, fresh_until: 100, body: {} });
  assert.equal(await c.get("a"), undefined);
  assert.ok(await c.get("b"));
  assert.ok(await c.get("c"));
});

test("get bumps to MRU", async () => {
  const c = new InMemoryStatusCache(2);
  await c.set("a", { fetched_at: 1, fresh_until: 100, body: {} });
  await c.set("b", { fetched_at: 2, fresh_until: 100, body: {} });
  await c.get("a");
  await c.set("c", { fetched_at: 3, fresh_until: 100, body: {} });
  assert.ok(await c.get("a"));
  assert.equal(await c.get("b"), undefined);
});

test("maxEntries=1 evicts on every new key", async () => {
  const c = new InMemoryStatusCache(1);
  await c.set("a", { fetched_at: 1, fresh_until: 100, body: {} });
  await c.set("b", { fetched_at: 2, fresh_until: 100, body: {} });
  assert.equal(await c.get("a"), undefined);
  assert.ok(await c.get("b"));
});

test("rejects non-positive maxEntries", () => {
  assert.throws(() => new InMemoryStatusCache(0), /positive integer/);
  assert.throws(() => new InMemoryStatusCache(-1), /positive integer/);
  assert.throws(() => new InMemoryStatusCache(1.5), /positive integer/);
});

test("re-set on same URL replaces (not duplicates) and bumps to MRU", async () => {
  const c = new InMemoryStatusCache(2);
  await c.set("a", { fetched_at: 1, fresh_until: 100, body: { v: 1 } });
  await c.set("b", { fetched_at: 2, fresh_until: 100, body: { v: 2 } });
  // Re-set "a" — must replace (not push count to 3) and bump "a" to MRU.
  await c.set("a", { fetched_at: 10, fresh_until: 200, body: { v: 99 } });
  // Adding "c" should now evict "b" (which is the LRU after the re-set bumped "a").
  await c.set("c", { fetched_at: 3, fresh_until: 100, body: { v: 3 } });
  const a = await c.get("a");
  assert.ok(a);
  // Body replaced with the latest set, no duplicate entry surviving.
  assert.deepEqual(a?.body, { v: 99 });
  assert.equal(a?.fetched_at, 10);
  assert.equal(await c.get("b"), undefined);
  assert.ok(await c.get("c"));
});
