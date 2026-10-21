/**
 * Tests for top-level verifyReceipt (envelope dispatch).
 *
 * Coverage:
 *   V1 — non-object input → schema_invalid.
 *   V2 — null input → schema_invalid.
 *   V3 — v=1 input → unsupported_envelope_version.
 *   V4 — missing v field → unsupported_envelope_version.
 *   V5 — v=2 input dispatches to verifyV2 (signature fails, envelope_version: 2).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyReceipt } from "../src/index.ts";

test("V1 — non-object input → schema_invalid", async () => {
  const result = await verifyReceipt("not-an-object");
  assert.equal(result.envelope_version, "unknown");
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "schema_invalid");
});

test("V2 — null input → schema_invalid", async () => {
  const result = await verifyReceipt(null);
  assert.equal(result.envelope_version, "unknown");
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "schema_invalid");
});

test("V3 — v=1 input → unsupported_envelope_version", async () => {
  const result = await verifyReceipt({ v: 1, claim_type: "ar.purpose.v1" });
  assert.equal(result.envelope_version, "unknown");
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "unsupported_envelope_version");
});

test("V4 — missing v field → unsupported_envelope_version", async () => {
  const result = await verifyReceipt({ claim_type: "ar.purpose.v1" });
  assert.equal(result.envelope_version, "unknown");
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "unsupported_envelope_version");
});

test("V5 — v=2 input dispatches to verifyV2 (signature fails, envelope_version 2)", async () => {
  const result = await verifyReceipt({
    v: 2,
    claim_type: "ar.purpose.v1",
    id: "r-001",
    iss: "did:web:dekimu.com",
    iss_key: "did:web:dekimu.com#key-1",
    iat: "2026-05-21T10:00:00Z",
    prev: null,
    subject: null,
    sig: "fakesig",
    body: {
      event_type: "binding",
      activity_id_commit: "sha256:" + "a".repeat(64),
      purpose_commit: "sha256:" + "b".repeat(64),
      purpose_class: "analytics",
      lawful_basis: "legitimate_interest",
      data_categories: ["usage"],
      data_subjects_class: "customers",
      policy_hash: "sha256:" + "c".repeat(64),
      minimisation_hash: "sha256:" + "d".repeat(64),
      consent_receipt_hash: null,
      retention_receipt_hash: null,
      transfer_arrangement_hash: null,
      bound_at: "2026-05-21T10:00:00Z",
    },
  });
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, false);
});
