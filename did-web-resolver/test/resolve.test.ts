import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  resolveDidWebKey,
  DidWebResolveError,
  InMemoryKeyCache,
  type KeyDocV1,
} from "../src/index.ts";

const ISS = "did:web:example.com";
// Real Ed25519 keypair so iss_key is the genuine base64url fingerprint of the SPKI's
// raw 32-byte key — resolveDidWebKey now binds the two (iss_key_fingerprint_mismatch).
const { publicKey: TEST_PUB } = generateKeyPairSync("ed25519");
const SPKI_DER = TEST_PUB.export({ type: "spki", format: "der" });
const SPKI_DER_B64 = Buffer.from(SPKI_DER).toString("base64");
const ISS_KEY =
  "ed25519:" + Buffer.from(SPKI_DER.subarray(SPKI_DER.length - 32)).toString("base64url");
// A second, unrelated key: its SPKI DER served under the legit ISS_KEY simulates a
// compromised issuer domain swapping in an attacker key under the real fingerprint.
const { publicKey: OTHER_PUB } = generateKeyPairSync("ed25519");
const OTHER_DER_B64 = Buffer.from(OTHER_PUB.export({ type: "spki", format: "der" })).toString(
  "base64",
);

// ML-DSA-65 (FIPS 204, v1.3 rollout R2). Needs Node ≥24.6. The raw 1952-byte
// public key has no SPKI framing — exported via JWK `pub` (kty AKP). The served
// key-doc value is base64 of that raw key; the fingerprint is its base64url.
function mlDsaRaw(pub: ReturnType<typeof generateKeyPairSync>["publicKey"]): Buffer {
  const jwk = pub.export({ format: "jwk" }) as { pub?: string };
  return Buffer.from(jwk.pub ?? "", "base64url");
}
const { publicKey: ML_PUB } = generateKeyPairSync("ml-dsa-65");
const ML_RAW = mlDsaRaw(ML_PUB);
const ML_RAW_B64 = ML_RAW.toString("base64");
const ML_ISS_KEY = "ml-dsa-65:" + ML_RAW.toString("base64url");
const { publicKey: ML_OTHER_PUB } = generateKeyPairSync("ml-dsa-65");
const ML_OTHER_RAW_B64 = mlDsaRaw(ML_OTHER_PUB).toString("base64");

function makeDoc(entries: Partial<KeyDocV1["keys"][number]>[]): KeyDocV1 {
  return {
    version: 1,
    keys: entries.map((e) => ({
      iss_key: e.iss_key ?? ISS_KEY,
      public_key_der_base64: e.public_key_der_base64 ?? SPKI_DER_B64,
      valid_from: e.valid_from ?? "2026-05-17T00:00:00Z",
      valid_until: e.valid_until ?? null,
    })),
  };
}

function fetcherFor(doc: unknown, status = 200): typeof fetch {
  return async () => new Response(JSON.stringify(doc), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("resolveDidWebKey", () => {
  it("returns SPKI DER bytes for a matching iss_key", async () => {
    const pub = await resolveDidWebKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: () => new Date("2026-06-01T00:00:00Z"),
    });
    assert.ok(pub instanceof Uint8Array);
    assert.equal(pub.length, 44); // SPKI prefix (12) + Ed25519 pub (32)
  });

  it("throws iss_key_fingerprint_mismatch when the served key bytes differ from the iss_key", async () => {
    // Entry matches the requested iss_key and is in-window, but the DER is a DIFFERENT key.
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: ISS_KEY,
        fetcher: fetcherFor(makeDoc([{ public_key_der_base64: OTHER_DER_B64 }])),
        now: () => new Date("2026-06-01T00:00:00Z"),
      }),
      (err: unknown) =>
        err instanceof DidWebResolveError && err.code === "iss_key_fingerprint_mismatch",
    );
  });

  it("does NOT cache a fingerprint-mismatched key (never persists a forged key)", async () => {
    const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000 });
    const fetcher = fetcherFor(makeDoc([{ public_key_der_base64: OTHER_DER_B64 }]));
    const now = () => new Date("2026-06-01T00:00:00Z");
    await assert.rejects(resolveDidWebKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache, now }));
    assert.equal(cache.get(`${ISS}#${ISS_KEY}`), undefined);
  });

  it("throws no_matching_key when iss_key absent from doc", async () => {
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: "ed25519:DIFFERENT",
        fetcher: fetcherFor(makeDoc([{}])),
        now: () => new Date("2026-06-01T00:00:00Z"),
      }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "no_matching_key",
    );
  });

  it("throws key_not_yet_valid before valid_from", async () => {
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: ISS_KEY,
        fetcher: fetcherFor(makeDoc([{ valid_from: "2026-06-01T00:00:00Z" }])),
        now: () => new Date("2026-05-17T00:00:00Z"),
      }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "key_not_yet_valid",
    );
  });

  it("throws key_no_longer_valid after valid_until", async () => {
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: ISS_KEY,
        fetcher: fetcherFor(makeDoc([{ valid_until: "2026-05-01T00:00:00Z" }])),
        now: () => new Date("2026-05-17T00:00:00Z"),
      }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "key_no_longer_valid",
    );
  });

  it("throws non_200 on HTTP error", async () => {
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: ISS_KEY,
        fetcher: fetcherFor({}, 404),
      }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "non_200",
    );
  });

  it("throws json_parse on invalid JSON", async () => {
    const fetcher: typeof fetch = async () => new Response("{not json", { status: 200 });
    await assert.rejects(
      resolveDidWebKey({ iss: ISS, iss_key: ISS_KEY, fetcher }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "json_parse",
    );
  });

  it("throws fetch_failed when fetcher rejects", async () => {
    const fetcher: typeof fetch = async () => { throw new Error("network down"); };
    await assert.rejects(
      resolveDidWebKey({ iss: ISS, iss_key: ISS_KEY, fetcher }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "fetch_failed",
    );
  });

  it("throws invalid_public_key_encoding for non-base64 key bytes", async () => {
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: ISS_KEY,
        fetcher: fetcherFor(makeDoc([{ public_key_der_base64: "!!!not base64!!!" }])),
        now: () => new Date("2026-06-01T00:00:00Z"),
      }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "invalid_public_key_encoding",
    );
  });

  it("uses the cache on second call for the same iss", async () => {
    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls++;
      return new Response(JSON.stringify(makeDoc([{}])), { status: 200 });
    };
    const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000, now: () => 1000 });
    await resolveDidWebKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache, now: () => new Date("2026-06-01T00:00:00Z") });
    await resolveDidWebKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache, now: () => new Date("2026-06-01T00:00:00Z") });
    assert.equal(calls, 1);
  });

  it("writes a negative-cache entry on non_200 and throws negative_cached on retry", async () => {
    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls++;
      return new Response("", { status: 503 });
    };
    const cache = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 30_000,
      now: () => 1000,
    });
    await assert.rejects(
      resolveDidWebKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "non_200",
    );
    await assert.rejects(
      resolveDidWebKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "negative_cached",
    );
    assert.equal(calls, 1);
  });

  it("writes a negative-cache entry on no_matching_key and throws negative_cached on retry", async () => {
    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls++;
      return new Response(JSON.stringify(makeDoc([{}])), { status: 200 });
    };
    const cache = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 30_000,
      now: () => 1000,
    });
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: "ed25519:OTHER",
        fetcher,
        cache,
        now: () => new Date("2026-06-01T00:00:00Z"),
      }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "no_matching_key",
    );
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: "ed25519:OTHER",
        fetcher,
        cache,
        now: () => new Date("2026-06-01T00:00:00Z"),
      }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "negative_cached",
    );
    assert.equal(calls, 1);
  });

  it("does NOT negative-cache fetch_failed (transient network errors retry on next call)", async () => {
    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls++;
      if (calls === 1) throw new Error("network down");
      return new Response(JSON.stringify(makeDoc([{}])), { status: 200 });
    };
    const cache = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 30_000,
      now: () => 1000,
    });
    await assert.rejects(
      resolveDidWebKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "fetch_failed",
    );
    const pub = await resolveDidWebKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher,
      cache,
      now: () => new Date("2026-06-01T00:00:00Z"),
    });
    assert.ok(pub instanceof Uint8Array);
    assert.equal(calls, 2);
  });

  it("does NOT negative-cache window violations (key_not_yet_valid)", async () => {
    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls++;
      return new Response(
        JSON.stringify(makeDoc([{ valid_from: "2026-06-01T00:00:00Z" }])),
        { status: 200 },
      );
    };
    const cache = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 30_000,
      now: () => 1000,
    });
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: ISS_KEY,
        fetcher,
        cache,
        now: () => new Date("2026-05-17T00:00:00Z"),
      }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "key_not_yet_valid",
    );
    // Window violations are stable but rare — the resolver does NOT negative-cache
    // them, so the next call re-fetches and re-validates.
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: ISS_KEY,
        fetcher,
        cache,
        now: () => new Date("2026-05-17T00:00:00Z"),
      }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "key_not_yet_valid",
    );
    assert.equal(calls, 2);
  });

  it("recovers from a negative cache after negativeTtlMs elapses", async () => {
    let calls = 0;
    let nowMs = 1000;
    const fetcher: typeof fetch = async () => {
      calls++;
      // First call fails with 503; later calls succeed.
      if (calls === 1) return new Response("", { status: 503 });
      return new Response(JSON.stringify(makeDoc([{}])), { status: 200 });
    };
    const cache = new InMemoryKeyCache({
      maxEntries: 4,
      ttlMs: 60_000,
      negativeTtlMs: 500,
      now: () => nowMs,
    });
    await assert.rejects(
      resolveDidWebKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "non_200",
    );
    nowMs = 1100; // still inside negative window
    await assert.rejects(
      resolveDidWebKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "negative_cached",
    );
    nowMs = 1600; // past negativeTtlMs (500ms)
    const pub = await resolveDidWebKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher,
      cache,
      now: () => new Date("2026-06-01T00:00:00Z"),
    });
    assert.ok(pub instanceof Uint8Array);
    assert.equal(calls, 2);
  });
});

describe("resolveDidWebKey — ml-dsa-65 (v1.3 rollout R2)", () => {
  const NOW = () => new Date("2026-06-01T00:00:00Z");
  function mlDoc(entries: Partial<KeyDocV1["keys"][number]>[]): KeyDocV1 {
    return {
      version: 1,
      keys: entries.map((e) => ({
        iss_key: e.iss_key ?? ML_ISS_KEY,
        public_key_der_base64: e.public_key_der_base64 ?? ML_RAW_B64,
        valid_from: e.valid_from ?? "2026-05-17T00:00:00Z",
        valid_until: e.valid_until ?? null,
      })),
    };
  }

  it("returns the raw 1952-byte key for a matching ml-dsa-65 iss_key", async () => {
    const pub = await resolveDidWebKey({
      iss: ISS,
      iss_key: ML_ISS_KEY,
      fetcher: fetcherFor(mlDoc([{}])),
      now: NOW,
    });
    assert.ok(pub instanceof Uint8Array);
    assert.equal(pub.length, 1952); // raw ML-DSA-65 public key, no SPKI framing
    assert.deepEqual(Buffer.from(pub), ML_RAW);
  });

  it("throws iss_key_fingerprint_mismatch when a DIFFERENT ml-dsa key is served under the legit fingerprint", async () => {
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: ML_ISS_KEY,
        fetcher: fetcherFor(mlDoc([{ public_key_der_base64: ML_OTHER_RAW_B64 }])),
        now: NOW,
      }),
      (err: unknown) =>
        err instanceof DidWebResolveError && err.code === "iss_key_fingerprint_mismatch",
    );
  });

  it("throws iss_key_fingerprint_mismatch when an ed25519-length key is served under an ml-dsa-65 fingerprint", async () => {
    // Cross-alg confusion: a 44-byte ed25519 SPKI can never satisfy the 1952-byte
    // ml-dsa binding — the length check rejects it before any byte compare.
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: ML_ISS_KEY,
        fetcher: fetcherFor(mlDoc([{ public_key_der_base64: SPKI_DER_B64 }])),
        now: NOW,
      }),
      (err: unknown) =>
        err instanceof DidWebResolveError && err.code === "iss_key_fingerprint_mismatch",
    );
  });

  it("does NOT cache a fingerprint-mismatched ml-dsa key", async () => {
    const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000 });
    await assert.rejects(
      resolveDidWebKey({
        iss: ISS,
        iss_key: ML_ISS_KEY,
        fetcher: fetcherFor(mlDoc([{ public_key_der_base64: ML_OTHER_RAW_B64 }])),
        cache,
        now: NOW,
      }),
    );
    assert.equal(cache.get(`${ISS}#${ML_ISS_KEY}`), undefined);
  });
});
