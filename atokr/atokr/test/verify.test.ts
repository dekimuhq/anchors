/**
 * Tests for top-level verifyReceipt (envelope dispatch).
 *
 * Coverage:
 *   V1 — null input → schema_invalid.
 *   V2 — v=1 input → unsupported_envelope_version.
 *   V3 — v=2 without resolveKey → signature_valid: false (no_key_resolver).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyReceipt } from "../src/index.ts";

test("V1 — null input → schema_invalid", async () => {
  const result = await verifyReceipt(null);
  assert.equal(result.envelope_version, "unknown");
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "schema_invalid");
});

test("V2 — v=1 input → unsupported_envelope_version", async () => {
  const result = await verifyReceipt({ v: 1, claim_type: "ar.tokenization.v1" });
  assert.equal(result.envelope_version, "unknown");
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "unsupported_envelope_version");
});

test("V3 — v=2 without resolveKey → signature_valid: false", async () => {
  const result = await verifyReceipt({
    v: 2,
    claim_type: "ar.tokenization.v1",
    id: "r-001",
    iss: "did:web:dekimu.com",
    iss_key: "did:web:dekimu.com#key-1",
    iat: "2026-05-21T10:00:00Z",
    prev: null,
    subject: "sha256:" + "a".repeat(64),
    sig: "fakesig",
    body: {
      event_type: "token.issued",
      token_id: "tok-001",
      format_class: "email",
      scope: {
        audience: "did:web:a.example.com",
        purpose: "test",
        valid_from: "2026-01-01T00:00:00Z",
        valid_until: null,
        single_use: false,
      },
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
    },
  });
  assert.equal(result.signature_valid, false);
});
