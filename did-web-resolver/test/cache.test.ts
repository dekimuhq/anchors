import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { InMemoryKeyCache, type KeyCache } from "../src/index.ts";

describe("InMemoryKeyCache", () => {
  it("stores and returns a value before expiry", () => {
    let now = 1000;
    const c: KeyCache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 500, now: () => now });
    c.set("k", "v");
    assert.equal(c.get("k"), "v");
  });

  it("returns undefined after TTL elapses (exclusive boundary)", () => {
    let now = 1000;
    const c: KeyCache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 500, now: () => now });
    c.set("k", "v");
    now = 1499;
    assert.equal(c.get("k"), "v");
    now = 1500;
    assert.equal(c.get("k"), undefined);
  });

  it("LRU-evicts the least-recently-used entry past maxEntries", () => {
    let now = 1000;
    const c = new InMemoryKeyCache({ maxEntries: 2, ttlMs: 60_000, now: () => now });
    c.set("a", "1");
    c.set("b", "2");
    c.get("a"); // bumps a
    c.set("c", "3"); // evicts b
    assert.equal(c.get("a"), "1");
    assert.equal(c.get("b"), undefined);
    assert.equal(c.get("c"), "3");
  });

  it("rejects non-positive maxEntries at construction", () => {
    assert.throws(
      () => new InMemoryKeyCache({ maxEntries: 0, ttlMs: 1, now: () => 1 }),
      /maxEntries/,
    );
    assert.throws(
      () => new InMemoryKeyCache({ maxEntries: -1, ttlMs: 1, now: () => 1 }),
      /maxEntries/,
    );
  });

  it("clear() empties the cache", () => {
    const c = new InMemoryKeyCache({ maxEntries: 2, ttlMs: 1000, now: () => 1 });
    c.set("a", "x");
    c.clear();
    assert.equal(c.get("a"), undefined);
  });

  it("rejects negative negativeTtlMs at construction", () => {
    assert.throws(
      () => new InMemoryKeyCache({ maxEntries: 2, ttlMs: 1, negativeTtlMs: -1, now: () => 1 }),
      /negativeTtlMs/,
    );
  });
});

describe("InMemoryKeyCache — negative caching", () => {
  it("getNegative returns undefined when negativeTtlMs is 0 (default)", () => {
    const c = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000, now: () => 1000 });
    c.setNegative("k", "non_200:404");
    assert.equal(c.getNegative("k"), undefined);
  });

  it("setNegative is a no-op when negativeTtlMs is 0", () => {
    const c = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000, now: () => 1000 });
    c.setNegative("k", "non_200:404");
    // The map should still be empty — no positive nor negative entry stored.
    assert.equal(c.get("k"), undefined);
  });

  it("getNegative returns the cached error code within negativeTtlMs", () => {
    let now = 1000;
    const c = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 500,
      now: () => now,
    });
    c.setNegative("k", "no_matching_key");
    assert.equal(c.getNegative("k"), "no_matching_key");
    now = 1499;
    assert.equal(c.getNegative("k"), "no_matching_key");
  });

  it("getNegative returns undefined after negativeTtlMs elapses (exclusive boundary)", () => {
    let now = 1000;
    const c = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 500,
      now: () => now,
    });
    c.setNegative("k", "non_200:500");
    now = 1500;
    assert.equal(c.getNegative("k"), undefined);
  });

  it("get returns undefined when the entry is negative-typed (no positive-negative confusion)", () => {
    const c = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 500,
      now: () => 1000,
    });
    c.setNegative("k", "non_200:404");
    assert.equal(c.get("k"), undefined);
  });

  it("getNegative returns undefined when the entry is positive-typed", () => {
    const c = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 500,
      now: () => 1000,
    });
    c.set("k", "value");
    assert.equal(c.getNegative("k"), undefined);
  });

  it("set overrides a prior negative entry on the same key", () => {
    const c = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 500,
      now: () => 1000,
    });
    c.setNegative("k", "no_matching_key");
    c.set("k", "value");
    assert.equal(c.get("k"), "value");
    assert.equal(c.getNegative("k"), undefined);
  });

  it("setNegative overrides a prior positive entry on the same key", () => {
    const c = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 500,
      now: () => 1000,
    });
    c.set("k", "value");
    c.setNegative("k", "non_200:503");
    assert.equal(c.get("k"), undefined);
    assert.equal(c.getNegative("k"), "non_200:503");
  });

  it("clear() empties both positive and negative entries", () => {
    const c = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 500,
      now: () => 1000,
    });
    c.set("a", "x");
    c.setNegative("b", "no_matching_key");
    c.clear();
    assert.equal(c.get("a"), undefined);
    assert.equal(c.getNegative("b"), undefined);
  });

  it("LRU-evicts negative entries the same as positive entries past maxEntries", () => {
    const c = new InMemoryKeyCache({
      maxEntries: 2,
      ttlMs: 60_000,
      negativeTtlMs: 60_000,
      now: () => 1000,
    });
    c.setNegative("a", "x");
    c.setNegative("b", "y");
    c.setNegative("c", "z"); // evicts a
    assert.equal(c.getNegative("a"), undefined);
    assert.equal(c.getNegative("b"), "y");
    assert.equal(c.getNegative("c"), "z");
  });

  it("getNegative bumps recency (LRU-aware)", () => {
    const c = new InMemoryKeyCache({
      maxEntries: 2,
      ttlMs: 60_000,
      negativeTtlMs: 60_000,
      now: () => 1000,
    });
    c.setNegative("a", "x");
    c.setNegative("b", "y");
    c.getNegative("a"); // bumps a
    c.setNegative("c", "z"); // evicts b
    assert.equal(c.getNegative("a"), "x");
    assert.equal(c.getNegative("b"), undefined);
    assert.equal(c.getNegative("c"), "z");
  });
});
