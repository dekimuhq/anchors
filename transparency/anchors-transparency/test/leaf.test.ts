import { test } from "node:test";
import assert from "node:assert/strict";
import { leafHash } from "../src/leaf.ts";

test("leafHash ignores the incl block (logging never changes the leaf)", () => {
  const base = { v: 2, claim_type: "ar.provenance.v1", iss: "did:web:example.com", sig: "AAAA", anchor: null };
  const withIncl = { ...base, incl: { log_id: "x", leaf: "sha256:00", promise: { timestamp: "2026-01-01T00:00:00Z", sig: "BBBB" } } };
  assert.equal(leafHash(base), leafHash(withIncl));
});

test("leafHash is sensitive to every non-incl field", () => {
  const a = { v: 2, claim_type: "ar.provenance.v1", sig: "AAAA" };
  const b = { v: 2, claim_type: "ar.consent.v1", sig: "AAAA" };
  assert.notEqual(leafHash(a), leafHash(b));
});

test("leafHash returns self-describing sha256: prefix", () => {
  assert.match(leafHash({ v: 2 }), /^sha256:[0-9a-f]{64}$/);
});
