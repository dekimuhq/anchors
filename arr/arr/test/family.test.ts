/**
 * Tests for the ARR family manifest (Phase A.3 step 2 — defineFamily()
 * adoption mirroring the ALR canary at `a7ae33c` and the APR step at
 * Phase A.3 step 1).
 *
 * Asserts:
 *   - Manifest meta matches FAMILY-CONSISTENCY.md (chip #3, status_list_slot=3,
 *     subject must-be-present, TSA free upgrade path, six owned claim_types
 *     including ar.batch.v1).
 *   - `isOwnedClaimType` reflects the ARR v=2 claim_type allowlist; rejects
 *     v=1-internal kinds (`arr.hold_extension.v1`, etc.) which are NOT part of
 *     the v=2 shared envelope union.
 *   - `checkSubjectPresence` mirrors the FAMILY-CONSISTENCY §3 rule for ARR
 *     (sha256:<hex> string OK, null/empty rejected).
 *
 * Public-API regression: `arrFamily` must be exported from the package
 * barrel. Importing from "../src/index.ts" guards that.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { arrFamily } from "../src/index.ts";

// ── meta ─────────────────────────────────────────────────────────────────────

test("arrFamily.meta matches FAMILY-CONSISTENCY (chip 3, slot 3, must-be-present, free TSA, batch=true)", () => {
  assert.equal(arrFamily.meta.acronym, "ARR");
  assert.equal(arrFamily.meta.name, "Anchored Retention Receipts");
  assert.equal(arrFamily.meta.chip, 3);
  assert.equal(arrFamily.meta.status_list_slot, 3);
  assert.equal(arrFamily.meta.subject_presence, "must-be-present");
  assert.equal(arrFamily.meta.tsa_upgrade_path, "free");
  assert.deepEqual([...arrFamily.meta.claim_types], [
    "ar.erasure.v1",
    "ar.expiry.v1",
    "ar.hold.v1",
    "ar.anonymization.v1",
    "ar.archive.v1",
    "ar.batch.v1",
  ]);
  assert.equal(arrFamily.meta.continuity, true);
  assert.equal(arrFamily.meta.batch, true);
  assert.equal(arrFamily.meta.predicate_recommended, false);
});

test("arrFamily.meta is frozen", () => {
  assert.equal(Object.isFrozen(arrFamily.meta), true);
  assert.equal(Object.isFrozen(arrFamily.meta.claim_types), true);
});

// ── isOwnedClaimType ─────────────────────────────────────────────────────────

test("isOwnedClaimType accepts all six v=2 ARR claim_types", () => {
  assert.equal(arrFamily.isOwnedClaimType("ar.erasure.v1"), true);
  assert.equal(arrFamily.isOwnedClaimType("ar.expiry.v1"), true);
  assert.equal(arrFamily.isOwnedClaimType("ar.hold.v1"), true);
  assert.equal(arrFamily.isOwnedClaimType("ar.anonymization.v1"), true);
  assert.equal(arrFamily.isOwnedClaimType("ar.archive.v1"), true);
  assert.equal(arrFamily.isOwnedClaimType("ar.batch.v1"), true);
});

test("isOwnedClaimType rejects sibling-family claim_types", () => {
  assert.equal(arrFamily.isOwnedClaimType("ar.provenance.v1"), false);
  assert.equal(arrFamily.isOwnedClaimType("ar.consent.v1"), false);
  assert.equal(arrFamily.isOwnedClaimType("ar.lineage.v1"), false);
  assert.equal(arrFamily.isOwnedClaimType("ar.notice.v1"), false);
  assert.equal(arrFamily.isOwnedClaimType(""), false);
});

// ── checkSubjectPresence ─────────────────────────────────────────────────────

test("checkSubjectPresence accepts sha256:<hex> subject", () => {
  const r = arrFamily.checkSubjectPresence(`sha256:${"a".repeat(64)}`);
  assert.equal(r.ok, true);
});

test("checkSubjectPresence rejects null", () => {
  const r = arrFamily.checkSubjectPresence(null);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "subject_must_be_present");
});

test("checkSubjectPresence rejects empty string", () => {
  const r = arrFamily.checkSubjectPresence("");
  assert.equal(r.ok, false);
});

// ── validateBody (pass-through, mirrors verifier behavior) ───────────────────

test("validateBody narrows non-null object input", () => {
  const body = { kind: "ar.erasure.v1", profile: "gdpr.art17" };
  const r = arrFamily.validateBody(body);
  assert.equal(r.ok, true);
});

test("validateBody rejects null", () => {
  const r = arrFamily.validateBody(null);
  assert.equal(r.ok, false);
});

// ── walkParents (ARR does not configure composition) ─────────────────────────

test("walkParents returns empty for ARR (no composition configured)", () => {
  const r = arrFamily.walkParents({ any: "body" });
  assert.deepEqual([...r], []);
});

// ── profile registry (gdpr.art17 from A2; 6 retention profiles 2026-05-30) ──

test("arrFamily registers gdpr.art17.erasure-finalized + the 6 retention profiles", () => {
  assert.deepEqual(
    [...arrFamily.profileIds],
    [
      "arr.gdpr.art17.erasure-finalized",
      "arr.gdpr.art5e",
      "arr.hipaa.retention",
      "arr.kyc.retention",
      "arr.sox.retention",
      "arr.mifid2.retention",
      "arr.aiact.art10",
    ],
  );
  assert.equal(arrFamily.hasProfile("arr.gdpr.art17.erasure-finalized"), true);
  assert.equal(arrFamily.hasProfile("arr.hipaa.retention"), true);
});
