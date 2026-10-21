/**
 * make-verify-issuer-trust smoke tests — Phase 3 of cross-issuer interop
 * Slice 2 (per 2026-05-19-anchors-verifier-trust-integration.md).
 *
 * The factory is a thin envelope→iss/iss_key extractor that delegates to
 * `verifyIssuerKey`. It does not introduce a parallel error taxonomy — invalid
 * input maps onto `iss_scheme_unsupported` from the underlying resolver.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { makeVerifyIssuerTrust } from "../src/make-verify-issuer-trust.ts";
import { InMemoryKeyCache } from "../src/cache.ts";
import type { TrustedIssuerRecord, TrustedIssuersSource } from "../src/trust-source.ts";

test("F1 non-object envelope → routes through verifyIssuerKey → iss_scheme_unsupported", async () => {
  const fn = makeVerifyIssuerTrust({});
  const r = await fn(null);
  assert.strictEqual(r.outcome, "invalid_key_doc");
  assert.strictEqual(r.reason, "iss_scheme_unsupported");
});

test("F2 envelope missing iss → routes through verifyIssuerKey → iss_scheme_unsupported", async () => {
  const fn = makeVerifyIssuerTrust({});
  const r = await fn({ iss_key: "ed25519:dummy" });
  assert.strictEqual(r.outcome, "invalid_key_doc");
  assert.strictEqual(r.reason, "iss_scheme_unsupported");
});

test("F3 envelope missing iss_key → routes through verifyIssuerKey → iss_scheme_unsupported (iss preserved)", async () => {
  const fn = makeVerifyIssuerTrust({});
  const r = await fn({ iss: "did:key:z6Mkdummy" });
  assert.strictEqual(r.outcome, "invalid_key_doc");
  assert.strictEqual(r.reason, "iss_scheme_unsupported");
  if (r.outcome === "invalid_key_doc") {
    assert.strictEqual(r.iss, "did:key:z6Mkdummy");
  }
});

test("F4 non-did:web iss → routes through verifyIssuerKey → iss_scheme_unsupported", async () => {
  const fn = makeVerifyIssuerTrust({});
  const r = await fn({ iss: "did:key:z6Mkdummy", iss_key: "ed25519:dummy" });
  assert.strictEqual(r.outcome, "invalid_key_doc");
  assert.strictEqual(r.reason, "iss_scheme_unsupported");
});

test("F5 onResolve option passes through to verifyIssuerKey", async () => {
  const events: Array<{ iss: string; iss_key: string; outcome: string }> = [];
  const fn = makeVerifyIssuerTrust({
    onResolve: (e) => events.push({ iss: e.iss, iss_key: e.iss_key, outcome: e.outcome }),
  });
  await fn({ iss: "did:key:z6Mkdummy", iss_key: "ed25519:dummy" });
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0]?.iss, "did:key:z6Mkdummy");
  assert.strictEqual(events[0]?.iss_key, "ed25519:dummy");
  assert.strictEqual(events[0]?.outcome, "invalid_key_doc");
});

test("F6 trustedIssuers option passes through (not consulted on scheme-rejection path)", async () => {
  let lookups = 0;
  const source: TrustedIssuersSource = {
    lookup: (_iss, _now): TrustedIssuerRecord | null => {
      lookups++;
      return null;
    },
  };
  const fn = makeVerifyIssuerTrust({ trustedIssuers: source });
  const r = await fn({ iss: "did:key:z6Mkdummy", iss_key: "ed25519:dummy" });
  assert.strictEqual(r.outcome, "invalid_key_doc");
  assert.strictEqual(lookups, 0, "trust source not consulted on scheme-rejection path");
});

test("F7 cache option is accepted and forwarded", async () => {
  const cache = new InMemoryKeyCache({ maxEntries: 4, ttlMs: 60_000 });
  const fn = makeVerifyIssuerTrust({ cache });
  const r = await fn({ iss: "did:key:z6Mkdummy", iss_key: "ed25519:dummy" });
  assert.strictEqual(r.outcome, "invalid_key_doc");
});

test("F8 factory is reusable across calls (no per-call state)", async () => {
  const fn = makeVerifyIssuerTrust({});
  const r1 = await fn({ iss: "did:key:z6Mkdummy", iss_key: "ed25519:dummy" });
  const r2 = await fn({ iss: "did:key:z6Mkother", iss_key: "ed25519:dummy" });
  assert.strictEqual(r1.outcome, "invalid_key_doc");
  assert.strictEqual(r2.outcome, "invalid_key_doc");
  if (r1.outcome === "invalid_key_doc" && r2.outcome === "invalid_key_doc") {
    assert.notStrictEqual(r1.iss, r2.iss, "factory does not mutate or cache iss across calls");
  }
});
