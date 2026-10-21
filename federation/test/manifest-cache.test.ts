import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ManifestCache } from "../src/manifest-cache.ts";
import { makeSignedManifest } from "./fixtures.ts";

describe("ManifestCache", () => {
  it("returns undefined on cache miss", () => {
    const cache = new ManifestCache();
    assert.equal(cache.get("did:web:unknown.example"), undefined);
  });

  it("stores and retrieves a manifest", () => {
    const cache = new ManifestCache();
    const { doc } = makeSignedManifest();
    cache.set("did:web:test.example", doc);
    const hit = cache.get("did:web:test.example");
    assert.equal(hit?.kind, "ar.issuer_manifest.v1");
  });

  it("stores and retrieves null (negative cache)", () => {
    const cache = new ManifestCache();
    cache.set("did:web:fail.example", null);
    const hit = cache.get("did:web:fail.example");
    assert.equal(hit, null);
  });

  it("expires positive entries after TTL", () => {
    const cache = new ManifestCache({ ttlMs: 100 });
    const { doc } = makeSignedManifest();
    const now = Date.now();
    cache.set("did:web:test.example", doc, now);
    assert.notEqual(cache.get("did:web:test.example", now + 50), undefined);
    assert.equal(cache.get("did:web:test.example", now + 101), undefined);
  });

  it("expires negative entries after negativeTtlMs", () => {
    const cache = new ManifestCache({ negativeTtlMs: 50 });
    const now = Date.now();
    cache.set("did:web:fail.example", null, now);
    assert.equal(cache.get("did:web:fail.example", now + 30), null);
    assert.equal(cache.get("did:web:fail.example", now + 51), undefined);
  });

  it("evicts oldest entry at capacity", () => {
    const cache = new ManifestCache({ maxEntries: 2 });
    const { doc: d1 } = makeSignedManifest({ iss: "did:web:a.example" });
    const { doc: d2 } = makeSignedManifest({ iss: "did:web:b.example" });
    const { doc: d3 } = makeSignedManifest({ iss: "did:web:c.example" });
    cache.set("did:web:a.example", d1);
    cache.set("did:web:b.example", d2);
    cache.set("did:web:c.example", d3);
    assert.equal(cache.get("did:web:a.example"), undefined); // evicted
    assert.notEqual(cache.get("did:web:b.example"), undefined);
    assert.notEqual(cache.get("did:web:c.example"), undefined);
  });

  it("does not evict when updating existing key", () => {
    const cache = new ManifestCache({ maxEntries: 2 });
    const { doc: d1 } = makeSignedManifest({ iss: "did:web:a.example" });
    const { doc: d2 } = makeSignedManifest({ iss: "did:web:b.example" });
    cache.set("did:web:a.example", d1);
    cache.set("did:web:b.example", d2);
    cache.set("did:web:a.example", d1); // update existing
    assert.equal(cache.size, 2);
    assert.notEqual(cache.get("did:web:a.example"), undefined);
    assert.notEqual(cache.get("did:web:b.example"), undefined);
  });

  it("delete removes entry", () => {
    const cache = new ManifestCache();
    const { doc } = makeSignedManifest();
    cache.set("did:web:test.example", doc);
    assert.equal(cache.delete("did:web:test.example"), true);
    assert.equal(cache.get("did:web:test.example"), undefined);
  });

  it("delete returns false for missing key", () => {
    const cache = new ManifestCache();
    assert.equal(cache.delete("did:web:missing.example"), false);
  });

  it("clear empties the cache", () => {
    const cache = new ManifestCache();
    const { doc } = makeSignedManifest();
    cache.set("did:web:a.example", doc);
    cache.set("did:web:b.example", doc);
    assert.equal(cache.size, 2);
    cache.clear();
    assert.equal(cache.size, 0);
  });

  it("size tracks entries", () => {
    const cache = new ManifestCache();
    assert.equal(cache.size, 0);
    cache.set("did:web:a.example", null);
    assert.equal(cache.size, 1);
    cache.set("did:web:b.example", null);
    assert.equal(cache.size, 2);
  });

  it("uses default options", () => {
    const cache = new ManifestCache();
    // Default maxEntries=128, ttlMs=5min, negativeTtlMs=30s
    const { doc } = makeSignedManifest();
    cache.set("did:web:test.example", doc);
    assert.notEqual(cache.get("did:web:test.example"), undefined);
  });

  it("positive TTL does not affect negative entries", () => {
    const cache = new ManifestCache({ ttlMs: 10_000, negativeTtlMs: 100 });
    const now = Date.now();
    cache.set("did:web:neg.example", null, now);
    // Still alive within negativeTtlMs
    assert.equal(cache.get("did:web:neg.example", now + 50), null);
    // Expired after negativeTtlMs (not ttlMs)
    assert.equal(cache.get("did:web:neg.example", now + 101), undefined);
  });

  it("negative TTL does not affect positive entries", () => {
    const cache = new ManifestCache({ ttlMs: 100, negativeTtlMs: 10_000 });
    const { doc } = makeSignedManifest();
    const now = Date.now();
    cache.set("did:web:pos.example", doc, now);
    assert.notEqual(cache.get("did:web:pos.example", now + 50), undefined);
    assert.equal(cache.get("did:web:pos.example", now + 101), undefined);
  });
});
