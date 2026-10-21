/**
 * Tests for the APR family manifest (Phase A.3 step 1 — defineFamily()
 * adoption mirroring the ALR canary at `a7ae33c`).
 *
 * Asserts:
 *   - Manifest meta matches FAMILY-CONSISTENCY.md (chip #1, status_list_slot=null
 *     since APR is the canonical Status List 2021 non-consumer, subject
 *     must-be-present, TSA free upgrade path, single owned claim_type).
 *   - `isOwnedClaimType` reflects the APR claim_type allowlist.
 *   - `checkSubjectPresence` mirrors the FAMILY-CONSISTENCY §3 rule for APR
 *     (free-form string OK, null/empty rejected).
 *
 * Public-API regression: `aprFamily` must be exported from the package
 * barrel. Importing from "../src/index.ts" guards that.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { aprFamily } from "../src/index.ts";

// ── meta ─────────────────────────────────────────────────────────────────────

test("aprFamily.meta matches FAMILY-CONSISTENCY (chip 1, slot null, must-be-present, free TSA)", () => {
  assert.equal(aprFamily.meta.acronym, "APR");
  assert.equal(aprFamily.meta.name, "Agent Provenance Receipts");
  assert.equal(aprFamily.meta.chip, 1);
  assert.equal(aprFamily.meta.status_list_slot, null);
  assert.equal(aprFamily.meta.subject_presence, "must-be-present");
  assert.equal(aprFamily.meta.tsa_upgrade_path, "free");
  assert.deepEqual([...aprFamily.meta.claim_types], ["ar.provenance.v1"]);
  assert.equal(aprFamily.meta.continuity, true);
  assert.equal(aprFamily.meta.batch, false);
  assert.equal(aprFamily.meta.predicate_recommended, false);
});

test("aprFamily.meta is frozen", () => {
  assert.equal(Object.isFrozen(aprFamily.meta), true);
  assert.equal(Object.isFrozen(aprFamily.meta.claim_types), true);
});

// ── isOwnedClaimType ─────────────────────────────────────────────────────────

test("isOwnedClaimType accepts ar.provenance.v1 only", () => {
  assert.equal(aprFamily.isOwnedClaimType("ar.provenance.v1"), true);
  assert.equal(aprFamily.isOwnedClaimType("ar.lineage.v1"), false);
  assert.equal(aprFamily.isOwnedClaimType("ar.consent.v1"), false);
  assert.equal(aprFamily.isOwnedClaimType("ar.erasure.v1"), false);
  assert.equal(aprFamily.isOwnedClaimType(""), false);
});

// ── checkSubjectPresence ─────────────────────────────────────────────────────

test("checkSubjectPresence accepts free-form subject string (artifact URL/id)", () => {
  const r = aprFamily.checkSubjectPresence("https://example.com/artifact/42");
  assert.equal(r.ok, true);
});

test("checkSubjectPresence accepts sha256:<hex>-shaped subject", () => {
  const r = aprFamily.checkSubjectPresence(`sha256:${"a".repeat(64)}`);
  assert.equal(r.ok, true);
});

test("checkSubjectPresence rejects null", () => {
  const r = aprFamily.checkSubjectPresence(null);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "subject_must_be_present");
});

test("checkSubjectPresence rejects empty string", () => {
  const r = aprFamily.checkSubjectPresence("");
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "subject_must_be_present");
});

test("checkSubjectPresence rejects undefined", () => {
  const r = aprFamily.checkSubjectPresence(undefined);
  assert.equal(r.ok, false);
});

// ── validateBody (pass-through, mirrors verifier behavior) ───────────────────

test("validateBody narrows non-null object input", () => {
  const body = { artifact: { type: "test", id: "x", hash: "h", hashAlgorithm: "sha256" } };
  const r = aprFamily.validateBody(body);
  assert.equal(r.ok, true);
});

test("validateBody rejects null", () => {
  const r = aprFamily.validateBody(null);
  assert.equal(r.ok, false);
});

test("validateBody rejects non-object input", () => {
  const r = aprFamily.validateBody("not-an-object");
  assert.equal(r.ok, false);
});

// ── walkParents (APR does not configure composition) ─────────────────────────

test("walkParents returns empty for APR (no composition configured)", () => {
  const r = aprFamily.walkParents({ any: "body" });
  assert.deepEqual([...r], []);
});

// ── profile registry (APR registers no profiles in Phase A.3) ────────────────

test("aprFamily has no registered profiles in Phase A.3", () => {
  assert.deepEqual([...aprFamily.profileIds], []);
  assert.deepEqual([...aprFamily.profileValidators], []);
});
