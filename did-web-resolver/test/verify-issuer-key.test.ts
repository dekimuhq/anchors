import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  verifyIssuerKey,
  InMemoryKeyCache,
  type KeyDocV1,
  type TrustedIssuerRecord,
  type TrustedIssuersSource,
  type VerifyIssuerKeyResolveEvent,
} from "../src/index.ts";

const ISS = "did:web:competitor.com";
// Real Ed25519 keypair so iss_key is the genuine base64url fingerprint of the SPKI's
// raw 32-byte key — resolveDidWebKey now binds the two (iss_key_fingerprint_mismatch).
const { publicKey: TEST_PUB } = generateKeyPairSync("ed25519");
const SPKI_DER = TEST_PUB.export({ type: "spki", format: "der" });
const SPKI_DER_B64 = Buffer.from(SPKI_DER).toString("base64");
const ISS_KEY =
  "ed25519:" + Buffer.from(SPKI_DER.subarray(SPKI_DER.length - 32)).toString("base64url");
const NOW = () => new Date("2026-06-01T00:00:00Z");

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

function trustedSource(records: TrustedIssuerRecord[]): TrustedIssuersSource {
  return {
    lookup(iss) {
      return records.find((r) => r.iss === iss) ?? null;
    },
  };
}

function record(overrides: Partial<TrustedIssuerRecord> = {}): TrustedIssuerRecord {
  return {
    iss: ISS,
    added_at: "2026-05-01T00:00:00Z",
    revoked_at: null,
    families: ["apr", "acr", "arr", "alr"],
    profiles_pinned: null,
    notes: null,
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────
// V1 — iss scheme dispatch (3 cases)
// ─────────────────────────────────────────────────────────────────────

describe("verifyIssuerKey — iss scheme dispatch", () => {
  it("V1.1 returns invalid_key_doc/iss_scheme_unsupported for did:key prefix", async () => {
    const result = await verifyIssuerKey({
      iss: "did:key:z6MkpTHR8VNsBxYAAAAAAA",
      iss_key: ISS_KEY,
    });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      assert.equal(result.reason, "iss_scheme_unsupported");
      assert.equal(result.spki, null);
      assert.equal(result.matched_record, null);
    }
  });

  it("V1.2 returns invalid_key_doc/iss_scheme_unsupported for raw URL", async () => {
    const result = await verifyIssuerKey({
      iss: "https://competitor.com",
      iss_key: ISS_KEY,
    });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      assert.equal(result.reason, "iss_scheme_unsupported");
    }
  });

  it("V1.3 returns invalid_key_doc/iss_scheme_unsupported for empty string", async () => {
    const result = await verifyIssuerKey({ iss: "", iss_key: ISS_KEY });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      assert.equal(result.reason, "iss_scheme_unsupported");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────
// V2 — happy-path × 5 outcomes (5 cases)
// ─────────────────────────────────────────────────────────────────────

describe("verifyIssuerKey — 5 outcomes", () => {
  it("V2.1 valid_trusted when issuer is on allowlist with revoked_at=null", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([record()]),
    });
    assert.equal(result.outcome, "valid_trusted");
    if (result.outcome === "valid_trusted") {
      assert.ok(result.spki instanceof Uint8Array);
      assert.ok(result.matched_record);
      assert.equal(result.matched_record.iss, ISS);
      assert.match(result.reason, /^trusted_since:2026-05-01/);
    }
  });

  it("V2.2 valid_untrusted when no TrustedIssuersSource is supplied (open trust)", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
    });
    assert.equal(result.outcome, "valid_untrusted");
    if (result.outcome === "valid_untrusted") {
      assert.equal(result.matched_record, null);
      assert.equal(result.reason, "no_trusted_issuers_source_supplied");
    }
  });

  it("V2.3 valid_untrusted when issuer is not on the allowlist", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([record({ iss: "did:web:somebody-else.example" })]),
    });
    assert.equal(result.outcome, "valid_untrusted");
    if (result.outcome === "valid_untrusted") {
      assert.equal(result.matched_record, null);
      assert.equal(result.reason, "issuer_not_on_allowlist");
    }
  });

  it("V2.4 valid_revoked when issuer record has revoked_at <= now", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([record({ revoked_at: "2026-05-28T00:00:00Z" })]),
    });
    assert.equal(result.outcome, "valid_revoked");
    if (result.outcome === "valid_revoked") {
      assert.ok(result.matched_record);
      assert.equal(result.matched_record.revoked_at, "2026-05-28T00:00:00Z");
      assert.match(result.reason, /^revoked_at:2026-05-28/);
    }
  });

  it("V2.5 invalid_key_doc when fetch returns 404 (resolver path)", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor({}, 404),
      now: NOW,
    });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      assert.equal(result.reason, "non_200");
      assert.equal(result.spki, null);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────
// V3 — invalid_signature mapping (3 cases)
// ─────────────────────────────────────────────────────────────────────

describe("verifyIssuerKey — invalid_signature mapping", () => {
  it("V3.1 maps no_matching_key to invalid_signature", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: "ed25519:NOTPRESENT",
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
    });
    assert.equal(result.outcome, "invalid_signature");
    if (result.outcome === "invalid_signature") {
      assert.equal(result.reason, "no_matching_key");
    }
  });

  it("V3.2 maps key_not_yet_valid to invalid_signature", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{ valid_from: "2026-07-01T00:00:00Z" }])),
      now: NOW,
    });
    assert.equal(result.outcome, "invalid_signature");
    if (result.outcome === "invalid_signature") {
      assert.equal(result.reason, "key_not_yet_valid");
    }
  });

  it("V3.3 maps key_no_longer_valid to invalid_signature", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{ valid_until: "2026-05-15T00:00:00Z" }])),
      now: NOW,
    });
    assert.equal(result.outcome, "invalid_signature");
    if (result.outcome === "invalid_signature") {
      assert.equal(result.reason, "key_no_longer_valid");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────
// V4 — invalid_key_doc mapping (5 cases)
// ─────────────────────────────────────────────────────────────────────

describe("verifyIssuerKey — invalid_key_doc mapping", () => {
  it("V4.1 maps fetch_failed to invalid_key_doc", async () => {
    const fetcher: typeof fetch = async () => { throw new Error("network down"); };
    const result = await verifyIssuerKey({ iss: ISS, iss_key: ISS_KEY, fetcher, now: NOW });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      assert.equal(result.reason, "fetch_failed");
    }
  });

  it("V4.2 maps json_parse to invalid_key_doc", async () => {
    const fetcher: typeof fetch = async () => new Response("{not json", { status: 200 });
    const result = await verifyIssuerKey({ iss: ISS, iss_key: ISS_KEY, fetcher, now: NOW });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      assert.equal(result.reason, "json_parse");
    }
  });

  it("V4.3 maps key_doc_invalid (wrong version) to invalid_key_doc", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor({ version: 2, keys: [] }),
      now: NOW,
    });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      assert.equal(result.reason, "key_doc_invalid");
    }
  });

  it("V4.4 maps invalid_public_key_encoding to invalid_key_doc", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{ public_key_der_base64: "!!!not base64!!!" }])),
      now: NOW,
    });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      assert.equal(result.reason, "invalid_public_key_encoding");
    }
  });

  it("V4.5 maps unsupported_did_method (e.g. did:web with empty domain) to invalid_key_doc", async () => {
    const result = await verifyIssuerKey({
      iss: "did:web:",
      iss_key: ISS_KEY,
    });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      // didWebToUrl rejects empty domain — exact error code is "invalid_did" or
      // similar from did-web-url; we accept any KEY_DOC_CODES code.
      assert.ok(["invalid_did", "unsupported_did_method"].includes(result.reason));
    }
  });
});

// ─────────────────────────────────────────────────────────────────────
// V5 — cache hit/miss accounting (5 cases)
// ─────────────────────────────────────────────────────────────────────

describe("verifyIssuerKey — cache hit/miss accounting", () => {
  it("V5.1 cacheHit=false on first call", async () => {
    let captured: VerifyIssuerKeyResolveEvent | undefined;
    const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000, now: () => 1000 });
    await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      cache,
      now: NOW,
      onResolve: (ev) => { captured = ev; },
    });
    assert.equal(captured?.cacheHit, false);
  });

  it("V5.2 cacheHit=true on second call with the same cache", async () => {
    const events: VerifyIssuerKeyResolveEvent[] = [];
    const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000, now: () => 1000 });
    const opts = {
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      cache,
      now: NOW,
      onResolve: (ev: VerifyIssuerKeyResolveEvent) => { events.push(ev); },
    };
    await verifyIssuerKey(opts);
    await verifyIssuerKey(opts);
    assert.equal(events.length, 2);
    assert.equal(events[0]?.cacheHit, false);
    assert.equal(events[1]?.cacheHit, true);
  });

  it("V5.3 cacheHit=false when no cache supplied", async () => {
    let captured: VerifyIssuerKeyResolveEvent | undefined;
    await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      onResolve: (ev) => { captured = ev; },
    });
    assert.equal(captured?.cacheHit, false);
  });

  it("V5.4 cacheHit=false on iss_scheme_unsupported (resolver never invoked)", async () => {
    let captured: VerifyIssuerKeyResolveEvent | undefined;
    await verifyIssuerKey({
      iss: "did:key:z6Mk",
      iss_key: ISS_KEY,
      onResolve: (ev) => { captured = ev; },
    });
    assert.equal(captured?.cacheHit, false);
  });

  it("V5.5 second call after cache eviction reports cacheHit=false again", async () => {
    let now = 1000;
    const events: VerifyIssuerKeyResolveEvent[] = [];
    const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 500, now: () => now });
    const opts = {
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      cache,
      now: NOW,
      onResolve: (ev: VerifyIssuerKeyResolveEvent) => { events.push(ev); },
    };
    await verifyIssuerKey(opts);
    now = 1600; // past ttlMs
    await verifyIssuerKey(opts);
    assert.equal(events[0]?.cacheHit, false);
    assert.equal(events[1]?.cacheHit, false);
  });
});

// ─────────────────────────────────────────────────────────────────────
// V6 — TrustedIssuersSource integration (8 cases)
// ─────────────────────────────────────────────────────────────────────

describe("verifyIssuerKey — TrustedIssuersSource integration", () => {
  it("V6.1 trusted source receives correct iss + now", async () => {
    let receivedIss: string | undefined;
    let receivedNow: Date | undefined;
    const src: TrustedIssuersSource = {
      lookup(iss, now) {
        receivedIss = iss;
        receivedNow = now;
        return null;
      },
    };
    await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: src,
    });
    assert.equal(receivedIss, ISS);
    assert.equal(receivedNow?.toISOString(), "2026-06-01T00:00:00.000Z");
  });

  it("V6.2 matched_record is the exact object the source returned", async () => {
    const rec = record({ notes: "Onboarded 2026-06-01 via federation handshake" });
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([rec]),
    });
    if (result.outcome === "valid_trusted") {
      assert.equal(result.matched_record, rec);
      assert.equal(result.matched_record?.notes, "Onboarded 2026-06-01 via federation handshake");
    } else {
      assert.fail("expected valid_trusted");
    }
  });

  it("V6.3 valid_revoked when revoked_at == now (boundary inclusive)", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([record({ revoked_at: "2026-06-01T00:00:00Z" })]),
    });
    assert.equal(result.outcome, "valid_revoked");
  });

  it("V6.4 valid_trusted when revoked_at is in the future", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([record({ revoked_at: "2030-01-01T00:00:00Z" })]),
    });
    assert.equal(result.outcome, "valid_trusted");
  });

  it("V6.5 source returning null is treated as 'not on allowlist'", async () => {
    const src: TrustedIssuersSource = { lookup: () => null };
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: src,
    });
    assert.equal(result.outcome, "valid_untrusted");
    if (result.outcome === "valid_untrusted") {
      assert.equal(result.reason, "issuer_not_on_allowlist");
      assert.equal(result.matched_record, null);
    }
  });

  it("V6.6 trusted source is NOT consulted on resolver failure (invalid_key_doc)", async () => {
    let consulted = false;
    const src: TrustedIssuersSource = {
      lookup: () => { consulted = true; return record(); },
    };
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor({}, 500),
      now: NOW,
      trustedIssuers: src,
    });
    assert.equal(result.outcome, "invalid_key_doc");
    assert.equal(consulted, false);
  });

  it("V6.7 trusted source is NOT consulted on resolver failure (invalid_signature)", async () => {
    let consulted = false;
    const src: TrustedIssuersSource = {
      lookup: () => { consulted = true; return record(); },
    };
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: "ed25519:WRONG",
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: src,
    });
    assert.equal(result.outcome, "invalid_signature");
    assert.equal(consulted, false);
  });

  it("V6.8 profiles_pinned is preserved on the matched_record", async () => {
    const rec = record({
      profiles_pinned: {
        "ar.consent.v1": ["acr.gdpr.art7", "acr.eprivacy.cookie"],
      },
    });
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([rec]),
    });
    if (result.outcome === "valid_trusted") {
      assert.deepEqual(result.matched_record?.profiles_pinned, {
        "ar.consent.v1": ["acr.gdpr.art7", "acr.eprivacy.cookie"],
      });
    } else {
      assert.fail("expected valid_trusted");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────
// V7 — onResolve observability hook (6 cases)
// ─────────────────────────────────────────────────────────────────────

describe("verifyIssuerKey — onResolve hook", () => {
  it("V7.1 fires exactly once per call (success path)", async () => {
    let calls = 0;
    await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      onResolve: () => { calls++; },
    });
    assert.equal(calls, 1);
  });

  it("V7.2 fires exactly once per call (resolver-failure path)", async () => {
    let calls = 0;
    await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor({}, 500),
      now: NOW,
      onResolve: () => { calls++; },
    });
    assert.equal(calls, 1);
  });

  it("V7.3 fires on iss_scheme_unsupported (before any network call)", async () => {
    let captured: VerifyIssuerKeyResolveEvent | undefined;
    await verifyIssuerKey({
      iss: "did:key:abc",
      iss_key: ISS_KEY,
      onResolve: (ev) => { captured = ev; },
    });
    assert.equal(captured?.outcome, "invalid_key_doc");
  });

  it("V7.4 reports the resolved outcome correctly", async () => {
    const captured: VerifyIssuerKeyResolveEvent[] = [];
    await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([record({ revoked_at: "2026-05-28T00:00:00Z" })]),
      onResolve: (ev) => { captured.push(ev); },
    });
    assert.equal(captured[0]?.outcome, "valid_revoked");
  });

  it("V7.5 durationMs is non-negative", async () => {
    let captured: VerifyIssuerKeyResolveEvent | undefined;
    await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      onResolve: (ev) => { captured = ev; },
    });
    assert.ok((captured?.durationMs ?? -1) >= 0);
  });

  it("V7.6 forwards iss and iss_key verbatim", async () => {
    let captured: VerifyIssuerKeyResolveEvent | undefined;
    await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      onResolve: (ev) => { captured = ev; },
    });
    assert.equal(captured?.iss, ISS);
    assert.equal(captured?.iss_key, ISS_KEY);
  });
});

// ─────────────────────────────────────────────────────────────────────
// V8 — Window violations × revocation interactions (8 cases)
// ─────────────────────────────────────────────────────────────────────

describe("verifyIssuerKey — window × revocation interactions", () => {
  it("V8.1 window-failure precedes allowlist check (key_not_yet_valid wins)", async () => {
    let consulted = false;
    const src: TrustedIssuersSource = { lookup: () => { consulted = true; return record(); } };
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{ valid_from: "2030-01-01T00:00:00Z" }])),
      now: NOW,
      trustedIssuers: src,
    });
    assert.equal(result.outcome, "invalid_signature");
    assert.equal(consulted, false);
  });

  it("V8.2 window-failure precedes allowlist check (key_no_longer_valid wins)", async () => {
    let consulted = false;
    const src: TrustedIssuersSource = { lookup: () => { consulted = true; return record(); } };
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{ valid_until: "2026-05-01T00:00:00Z" }])),
      now: NOW,
      trustedIssuers: src,
    });
    assert.equal(result.outcome, "invalid_signature");
    assert.equal(consulted, false);
  });

  it("V8.3 valid_revoked wins over valid_trusted even with valid window", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([record({ revoked_at: "2026-05-15T00:00:00Z" })]),
    });
    assert.equal(result.outcome, "valid_revoked");
  });

  it("V8.4 valid_revoked carries spki bytes (so caller can still inspect)", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([record({ revoked_at: "2026-05-15T00:00:00Z" })]),
    });
    if (result.outcome === "valid_revoked") {
      assert.ok(result.spki instanceof Uint8Array);
      assert.equal(result.spki.length, 44);
    } else {
      assert.fail("expected valid_revoked");
    }
  });

  it("V8.5 valid_trusted carries spki bytes", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([record()]),
    });
    if (result.outcome === "valid_trusted") {
      assert.ok(result.spki instanceof Uint8Array);
      assert.equal(result.spki.length, 44);
    } else {
      assert.fail("expected valid_trusted");
    }
  });

  it("V8.6 valid_untrusted carries spki bytes", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
    });
    if (result.outcome === "valid_untrusted") {
      assert.ok(result.spki instanceof Uint8Array);
      assert.equal(result.spki.length, 44);
    } else {
      assert.fail("expected valid_untrusted");
    }
  });

  it("V8.7 invalid_key_doc spki is null", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor({}, 500),
      now: NOW,
    });
    assert.equal(result.outcome, "invalid_key_doc");
    assert.equal(result.spki, null);
  });

  it("V8.8 invalid_signature spki is null", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{ valid_until: "2026-05-01T00:00:00Z" }])),
      now: NOW,
    });
    assert.equal(result.outcome, "invalid_signature");
    assert.equal(result.spki, null);
  });
});

// ─────────────────────────────────────────────────────────────────────
// V9 — Cache interaction with verifyIssuerKey (6 cases)
// ─────────────────────────────────────────────────────────────────────

describe("verifyIssuerKey — cache interaction", () => {
  it("V9.1 second call reuses cached SPKI (network not hit)", async () => {
    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls++;
      return new Response(JSON.stringify(makeDoc([{}])), { status: 200 });
    };
    const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000, now: () => 1000 });
    await verifyIssuerKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache, now: NOW });
    await verifyIssuerKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache, now: NOW });
    assert.equal(calls, 1);
  });

  it("V9.2 negative-cache short-circuits subsequent calls to invalid_key_doc/negative_cached", async () => {
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
    const r1 = await verifyIssuerKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache, now: NOW });
    const r2 = await verifyIssuerKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache, now: NOW });
    assert.equal(r1.outcome, "invalid_key_doc");
    assert.equal(r2.outcome, "invalid_key_doc");
    if (r2.outcome === "invalid_key_doc") {
      assert.equal(r2.reason, "negative_cached");
    }
    assert.equal(calls, 1);
  });

  it("V9.3 cache miss + success populates positive cache", async () => {
    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls++;
      return new Response(JSON.stringify(makeDoc([{}])), { status: 200 });
    };
    const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000, now: () => 1000 });
    await verifyIssuerKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache, now: NOW });
    assert.notEqual(cache.get(`${ISS}#${ISS_KEY}`), undefined);
    assert.equal(calls, 1);
  });

  it("V9.4 different iss_keys do not collide in cache", async () => {
    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls++;
      return new Response(
        JSON.stringify(makeDoc([{ iss_key: ISS_KEY }, { iss_key: "ed25519:BBBB" }])),
        { status: 200 },
      );
    };
    const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000, now: () => 1000 });
    await verifyIssuerKey({ iss: ISS, iss_key: ISS_KEY, fetcher, cache, now: NOW });
    await verifyIssuerKey({ iss: ISS, iss_key: "ed25519:BBBB", fetcher, cache, now: NOW });
    assert.equal(calls, 2); // each iss_key forces a separate fetch
  });

  it("V9.5 cache absence still produces correct outcome", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
    });
    assert.equal(result.outcome, "valid_untrusted");
  });

  it("V9.6 cache present + trusted source = valid_trusted", async () => {
    const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000, now: () => 1000 });
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      cache,
      now: NOW,
      trustedIssuers: trustedSource([record()]),
    });
    assert.equal(result.outcome, "valid_trusted");
  });
});

// ─────────────────────────────────────────────────────────────────────
// V10 — Result type discipline (6 cases)
// ─────────────────────────────────────────────────────────────────────

describe("verifyIssuerKey — result type discipline", () => {
  it("V10.1 always carries the iss verbatim", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
    });
    assert.equal(result.iss, ISS);
  });

  it("V10.2 always carries the iss_key verbatim", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
    });
    assert.equal(result.iss_key, ISS_KEY);
  });

  it("V10.3 iss preserved on invalid_key_doc", async () => {
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor({}, 500),
      now: NOW,
    });
    assert.equal(result.iss, ISS);
  });

  it("V10.4 iss preserved on iss_scheme_unsupported", async () => {
    const result = await verifyIssuerKey({
      iss: "did:key:abc",
      iss_key: ISS_KEY,
    });
    assert.equal(result.iss, "did:key:abc");
  });

  it("V10.5 reason is always a non-empty string", async () => {
    const outcomes = [
      // valid_trusted
      verifyIssuerKey({
        iss: ISS, iss_key: ISS_KEY,
        fetcher: fetcherFor(makeDoc([{}])), now: NOW,
        trustedIssuers: trustedSource([record()]),
      }),
      // valid_untrusted
      verifyIssuerKey({
        iss: ISS, iss_key: ISS_KEY,
        fetcher: fetcherFor(makeDoc([{}])), now: NOW,
      }),
      // valid_revoked
      verifyIssuerKey({
        iss: ISS, iss_key: ISS_KEY,
        fetcher: fetcherFor(makeDoc([{}])), now: NOW,
        trustedIssuers: trustedSource([record({ revoked_at: "2026-05-15T00:00:00Z" })]),
      }),
      // invalid_key_doc
      verifyIssuerKey({
        iss: ISS, iss_key: ISS_KEY,
        fetcher: fetcherFor({}, 404), now: NOW,
      }),
      // invalid_signature
      verifyIssuerKey({
        iss: ISS, iss_key: ISS_KEY,
        fetcher: fetcherFor(makeDoc([{ valid_until: "2026-05-01T00:00:00Z" }])), now: NOW,
      }),
    ];
    const results = await Promise.all(outcomes);
    for (const r of results) {
      assert.equal(typeof r.reason, "string");
      assert.ok(r.reason.length > 0);
    }
  });

  it("V10.6 valid_untrusted with no source vs not-on-allowlist produces distinct reasons", async () => {
    const noSource = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
    });
    const offList = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeDoc([{}])),
      now: NOW,
      trustedIssuers: trustedSource([record({ iss: "did:web:somebody-else.example" })]),
    });
    assert.equal(noSource.reason, "no_trusted_issuers_source_supplied");
    assert.equal(offList.reason, "issuer_not_on_allowlist");
    assert.notEqual(noSource.reason, offList.reason);
  });
});
