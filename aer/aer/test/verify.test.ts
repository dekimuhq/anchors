/**
 * Tests for top-level verifyReceipt (envelope dispatch).
 *
 * Coverage:
 *   V1 — null input → schema_invalid.
 *   V2 — v=1 input → unsupported_envelope_version.
 *   V3 — v=2 conformity receipt without resolveKey → signature_valid: false.
 *   V4 — v=2 transparency receipt without resolveKey → signature_valid: false.
 *   V5 — v=2 conformity receipt without TSA → tsa_state: tsa_recommended.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyReceipt } from "../src/index.ts";
import type { FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { makeConformityBody, makeTransparencyBody, sha256Hex } from "./_helpers/fixtures.ts";

test("V1 — null input → schema_invalid", async () => {
  const result = await verifyReceipt(null);
  assert.equal(result.envelope_version, "unknown");
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "schema_invalid");
});

test("V2 — v=1 input → unsupported_envelope_version", async () => {
  const result = await verifyReceipt({ v: 1, claim_type: "ar.evaluation.v1" });
  assert.equal(result.envelope_version, "unknown");
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "unsupported_envelope_version");
});

test("V3 — v=2 conformity receipt without resolveKey → signature_valid: false", async () => {
  const result = await verifyReceipt({
    v: 2,
    claim_type: "ar.evaluation.v1",
    id: "r-aer-001",
    iss: "did:web:provider.example",
    iss_key: "did:web:provider.example#key-1",
    iat: "2026-05-21T10:00:00Z",
    exp: null,
    prev: null,
    subject: null,
    sig: "fakesig",
    tsa: null,
    credentialStatus: null,
    anchor: null,
    body: makeConformityBody(),
  });
  assert.equal(result.signature_valid, false);
});

test("V4 — v=2 transparency receipt without resolveKey → signature_valid: false", async () => {
  const result = await verifyReceipt({
    v: 2,
    claim_type: "ar.evaluation.v1",
    id: "r-aer-002",
    iss: "did:web:deployer.example",
    iss_key: "did:web:deployer.example#key-1",
    iat: "2026-09-01T10:05:00Z",
    exp: null,
    prev: null,
    subject: sha256Hex(),
    sig: "fakesig",
    tsa: null,
    credentialStatus: null,
    anchor: null,
    body: makeTransparencyBody(),
  });
  assert.equal(result.signature_valid, false);
});

test("V5 — conformity receipt without resolveKey does not get tsa_recommended (upgrade gated on signature_valid)", async () => {
  // Without a resolveKey, signature fails → tsa_state won't be upgraded to
  // tsa_recommended even on a conformity event (upgrade is gated on
  // signature_valid in the factory).
  const receipt: Record<string, unknown> = {
    v: 2,
    claim_type: "ar.evaluation.v1",
    id: "r-aer-tsa",
    iss: "did:web:provider.example",
    iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    iat: "2026-05-21T00:00:00Z",
    exp: null,
    prev: null,
    subject: null,
    sig: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    tsa: null,
    credentialStatus: null,
    anchor: null,
    body: makeConformityBody(),
  };

  const result = await verifyReceipt(receipt) as FamilyVerifyResult;
  assert.equal(result.signature_valid, false);
  assert.notEqual(result.tsa_state, "tsa_recommended");
});
