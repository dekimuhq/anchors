/**
 * Tests for the ACR family manifest (Phase A.3 step 3 — defineFamily()
 * adoption mirroring the ALR canary at `a7ae33c` and the APR/ARR steps).
 *
 * Asserts:
 *   - Manifest meta matches FAMILY-CONSISTENCY.md (chip #2, status_list_slot=2,
 *     subject must-be-present, TSA free upgrade path, three owned claim_types).
 *   - `isOwnedClaimType` reflects the ACR claim_type allowlist (3 entries).
 *   - `checkSubjectPresence` mirrors the FAMILY-CONSISTENCY §3 rule for ACR
 *     (sha256:<hex> HMAC-salted commit OK, null/empty rejected).
 *
 * Public-API regression: `acrFamily` must be exported from the package
 * barrel. Importing from "../src/index.ts" guards that.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { acrFamily } from "../src/index.ts";

// ── meta ─────────────────────────────────────────────────────────────────────

test("acrFamily.meta matches FAMILY-CONSISTENCY (chip 2, slot 2, must-be-present, free TSA)", () => {
  assert.equal(acrFamily.meta.acronym, "ACR");
  assert.equal(acrFamily.meta.name, "Anchored Consent Receipts");
  assert.equal(acrFamily.meta.chip, 2);
  assert.equal(acrFamily.meta.status_list_slot, 2);
  assert.equal(acrFamily.meta.subject_presence, "must-be-present");
  assert.equal(acrFamily.meta.tsa_upgrade_path, "free");
  assert.deepEqual([...acrFamily.meta.claim_types], [
    "ar.consent.v1",
    "ar.modification.v1",
    "ar.withdrawal.v1",
  ]);
  assert.equal(acrFamily.meta.continuity, true);
  assert.equal(acrFamily.meta.batch, false);
  assert.equal(acrFamily.meta.predicate_recommended, false);
});

test("acrFamily.meta is frozen", () => {
  assert.equal(Object.isFrozen(acrFamily.meta), true);
  assert.equal(Object.isFrozen(acrFamily.meta.claim_types), true);
});

// ── isOwnedClaimType ─────────────────────────────────────────────────────────

test("isOwnedClaimType accepts all three ACR claim_types", () => {
  assert.equal(acrFamily.isOwnedClaimType("ar.consent.v1"), true);
  assert.equal(acrFamily.isOwnedClaimType("ar.modification.v1"), true);
  assert.equal(acrFamily.isOwnedClaimType("ar.withdrawal.v1"), true);
});

test("isOwnedClaimType rejects sibling-family claim_types", () => {
  assert.equal(acrFamily.isOwnedClaimType("ar.provenance.v1"), false);
  assert.equal(acrFamily.isOwnedClaimType("ar.erasure.v1"), false);
  assert.equal(acrFamily.isOwnedClaimType("ar.lineage.v1"), false);
  assert.equal(acrFamily.isOwnedClaimType("ar.notice.v1"), false);
  assert.equal(acrFamily.isOwnedClaimType(""), false);
});

// ── checkSubjectPresence ─────────────────────────────────────────────────────

test("checkSubjectPresence accepts sha256:<hex> HMAC-salted commit", () => {
  const r = acrFamily.checkSubjectPresence(`sha256:${"a".repeat(64)}`);
  assert.equal(r.ok, true);
});

test("checkSubjectPresence rejects null", () => {
  const r = acrFamily.checkSubjectPresence(null);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "subject_must_be_present");
});

test("checkSubjectPresence rejects empty string", () => {
  const r = acrFamily.checkSubjectPresence("");
  assert.equal(r.ok, false);
});

// ── validateBody (pass-through, mirrors verifier behavior) ───────────────────

test("validateBody narrows non-null object input", () => {
  const body = { kind: "ar.consent.v1", profile: "gdpr.art7" };
  const r = acrFamily.validateBody(body);
  assert.equal(r.ok, true);
});

test("validateBody rejects null", () => {
  const r = acrFamily.validateBody(null);
  assert.equal(r.ok, false);
});

// ── walkParents (ACR does not configure composition) ─────────────────────────

test("walkParents returns empty for ACR (no composition configured)", () => {
  const r = acrFamily.walkParents({ any: "body" });
  assert.deepEqual([...r], []);
});

// ── profile registry (ACR registers esig.accept@qes after A2 migration) ─────

test("acrFamily has esig.accept@qes profile registered", () => {
  assert.deepEqual([...acrFamily.profileIds], ["acr.esig.accept@qes"]);
  assert.equal(acrFamily.hasProfile("acr.esig.accept@qes"), true);
});
