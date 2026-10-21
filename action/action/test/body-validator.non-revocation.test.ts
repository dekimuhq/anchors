/**
 * AActR non-revocation proof: optional `non_revocation_proof` (A4 — additive).
 *
 * The body validator (`verifyActionBody`) shape-checks the stapled
 * non-revocation proof and enforces the credential-binding invariant. It does
 * NOT verify the signature — that is the runtime verifier's job
 * (`verifyNonRevocationProof` in @dekimuhq/action-profiles).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyActionBody } from "../src/verify-single.ts";
import { validBody, H } from "./_helpers/fixtures.ts";

/** The request_id_commit `validBody()` carries — the proof must bind to it. */
const REQUEST_ID_COMMIT = H("c");

/**
 * A well-formed stapled non-revocation proof for `credential_id`, bound by
 * `receipt_commit` to `validBody()`'s `request_id_commit` by default.
 */
function proof(credentialId: string, receiptCommit: string = REQUEST_ID_COMMIT) {
  return {
    credential_id: credentialId,
    status: "active",
    as_of: "2026-06-08T10:00:30.000Z",
    status_list_ref: "https://app.dekimu.com/mandates/status/1",
    receipt_commit: receiptCommit,
    sig: "AAAA",
  };
}

// ── Happy path ────────────────────────────────────────────────────────────────

test("NRP1: valid with a well-formed non_revocation_proof matching credential_id", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    non_revocation_proof: proof("adr-grant-123"),
  });
  assert.equal(r.valid, true, r.errors.join(","));
});

// ── Credential-binding invariant ───────────────────────────────────────────────

test("NRP2: rejects a credential_id mismatch between proof and body", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    non_revocation_proof: proof("adr-grant-OTHER"),
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("non_revocation_proof.credential_mismatch"));
});

test("NRP2b: rejects a receipt_commit that differs from body.request_id_commit", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    non_revocation_proof: proof("adr-grant-123", H("d")), // not request_id_commit
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("non_revocation_proof.receipt_mismatch"));
});

test("NRP3: rejects non_revocation_proof present without body.credential_id (orphan)", () => {
  const r = verifyActionBody({
    ...validBody(),
    non_revocation_proof: proof("adr-grant-123"),
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("non_revocation_proof.orphan"));
});

// ── Shape checks ────────────────────────────────────────────────────────────────

test("NRP4: rejects a non-object non_revocation_proof", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    non_revocation_proof: "nope",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("non_revocation_proof.invalid"));
});

test("NRP5: rejects status other than active", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    non_revocation_proof: { ...proof("adr-grant-123"), status: "revoked" },
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("non_revocation_proof.invalid"));
});

test("NRP6: rejects a non-RFC3339 as_of", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    non_revocation_proof: { ...proof("adr-grant-123"), as_of: "not-a-date" },
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("non_revocation_proof.as_of_invalid"));
});

test("NRP7: rejects an empty status_list_ref", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    non_revocation_proof: { ...proof("adr-grant-123"), status_list_ref: "" },
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("non_revocation_proof.invalid"));
});

test("NRP8: rejects an empty sig", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    non_revocation_proof: { ...proof("adr-grant-123"), sig: "" },
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("non_revocation_proof.invalid"));
});

test("NRP9: rejects an empty proof credential_id", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    non_revocation_proof: { ...proof("adr-grant-123"), credential_id: "" },
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("non_revocation_proof.invalid"));
});
