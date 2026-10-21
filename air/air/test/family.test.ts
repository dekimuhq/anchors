/**
 * Tests for the `airFamily` manifest (Phase 4B Task 1 — factory canary).
 *
 * Exercises the surface most likely to drift during migration: identity
 * invariants, the per-event subject-presence callback with the
 * `dpia.stakeholders_consulted` representative-org / NGO-review carve-out,
 * the (declarative-only) profile-keyed TSA mandate matrix, and the
 * manifest's pass-through body validator + profile registration. The
 * factory's `verifyReceipt` / `mintV2` surfaces are exercised through the
 * existing `envelope-v2.ts` and `mint-v2.ts` wrappers in their own test
 * suites once the Task 2 collapse lands.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { airFamily } from "../src/family.ts";

test("airFamily declares chip 13, status_list_slot 7, ar.impact.v1, continuity, free TSA path", () => {
  assert.equal(airFamily.meta.acronym, "AIR");
  assert.equal(airFamily.meta.name, "Anchored Impact-Assessment Receipts");
  assert.equal(airFamily.meta.chip, 13);
  assert.equal(airFamily.meta.status_list_slot, 7);
  assert.equal(airFamily.meta.subject_presence, "either");
  assert.equal(airFamily.meta.tsa_upgrade_path, "free");
  assert.equal(airFamily.meta.continuity, true);
  assert.equal(airFamily.meta.batch, false);
  assert.equal(airFamily.meta.predicate_recommended, false);
  assert.deepEqual([...airFamily.meta.claim_types], ["ar.impact.v1"]);
});

test("airFamily.isOwnedClaimType only accepts ar.impact.v1", () => {
  assert.equal(airFamily.isOwnedClaimType("ar.impact.v1"), true);
  assert.equal(airFamily.isOwnedClaimType("ar.notice.v1"), false);
  assert.equal(airFamily.isOwnedClaimType("ar.breach.v1"), false);
  assert.equal(airFamily.isOwnedClaimType("ar.consent.v1"), false);
  assert.equal(airFamily.isOwnedClaimType("ar.impact.v2"), false);
});

test("airFamily.checkSubjectPresence — non-stakeholder events require subject: null", () => {
  for (const event_type of [
    "dpia.threshold_triggered",
    "dpia.scope_locked",
    "dpia.dpo_advised",
    "dpia.completed",
    "dpia.reviewed",
    "dpia.prior_consultation_initiated",
    "dpia.prior_consultation_resolved",
    "dpia.processing_authorised",
    "dpia.processing_blocked",
    "dpia.terminated",
  ]) {
    const body = { event_type };
    assert.deepEqual(
      airFamily.checkSubjectPresence(null, body),
      { ok: true },
      `null subject MUST be accepted for ${event_type}`,
    );
    assert.deepEqual(
      airFamily.checkSubjectPresence("sha256:" + "a".repeat(64), body),
      { ok: false, reason: "subject_present" },
      `sha256 subject MUST be rejected for ${event_type}`,
    );
    assert.deepEqual(
      airFamily.checkSubjectPresence("bogus", body),
      { ok: false, reason: "subject_present" },
      `arbitrary string MUST be rejected for ${event_type}`,
    );
  }
});

test("airFamily.checkSubjectPresence — dpia.stakeholders_consulted accepts null by default", () => {
  const body = { event_type: "dpia.stakeholders_consulted" };
  assert.deepEqual(airFamily.checkSubjectPresence(null, body), { ok: true });
});

test("airFamily.checkSubjectPresence — stakeholders_consulted + sha256 subject requires representative_org or ngo_review method", () => {
  const sha = "sha256:" + "b".repeat(64);
  for (const consultation_method of ["representative_org", "ngo_review"]) {
    const body = { event_type: "dpia.stakeholders_consulted", consultation_method };
    assert.deepEqual(
      airFamily.checkSubjectPresence(sha, body),
      { ok: true },
      `sha256 subject MUST be accepted with method ${consultation_method}`,
    );
  }
  for (const consultation_method of [
    "survey",
    "focus_group",
    "public_consultation",
    "internal_advisory_panel",
    "other",
  ]) {
    const body = { event_type: "dpia.stakeholders_consulted", consultation_method };
    assert.deepEqual(
      airFamily.checkSubjectPresence(sha, body),
      { ok: false, reason: "representative_subject_method_mismatch" },
      `sha256 subject MUST be rejected with method ${consultation_method}`,
    );
  }
});

test("airFamily.checkSubjectPresence — stakeholders_consulted with malformed subject rejects with subject_invalid_form", () => {
  const body = { event_type: "dpia.stakeholders_consulted", consultation_method: "representative_org" };
  assert.deepEqual(
    airFamily.checkSubjectPresence("nothex", body),
    { ok: false, reason: "subject_invalid_form" },
  );
  assert.deepEqual(
    airFamily.checkSubjectPresence("sha256:zzzz", body),
    { ok: false, reason: "subject_invalid_form" },
  );
  assert.deepEqual(
    airFamily.checkSubjectPresence("sha256:" + "A".repeat(64), body),
    { ok: false, reason: "subject_invalid_form" },
    "uppercase hex MUST be rejected (sha256:<lowercase-hex> form per v1.1 envelope §5.4)",
  );
});

test("airFamily.tsaMandateLevel — all five v1 profiles are recommended (event-keyed matrix handled in wrapper)", () => {
  assert.equal(
    airFamily.tsaMandateLevel("impact.art35_3_a_automated_decisions"),
    "recommended",
  );
  assert.equal(
    airFamily.tsaMandateLevel("impact.art35_3_b_large_scale_special_categories"),
    "recommended",
  );
  assert.equal(
    airFamily.tsaMandateLevel("impact.art35_3_c_public_monitoring"),
    "recommended",
  );
  assert.equal(airFamily.tsaMandateLevel("impact.art35_4_dpa_list"), "recommended");
  assert.equal(airFamily.tsaMandateLevel("impact.voluntary"), "recommended");
});

test("airFamily.tsaMandateLevel returns optional for unknown profile ids", () => {
  assert.equal(airFamily.tsaMandateLevel("impact.unknown"), "optional");
  assert.equal(airFamily.tsaMandateLevel(""), "optional");
});

test("airFamily registers all 5 v1 profiles in spec order", () => {
  assert.deepEqual([...airFamily.profileIds], [
    "impact.art35_3_a_automated_decisions",
    "impact.art35_3_b_large_scale_special_categories",
    "impact.art35_3_c_public_monitoring",
    "impact.art35_4_dpa_list",
    "impact.voluntary",
  ]);
  for (const id of airFamily.profileIds) {
    assert.equal(airFamily.hasProfile(id), true);
  }
  assert.equal(airFamily.hasProfile("impact.unknown"), false);
  assert.equal(airFamily.profileValidators.length, 5);
  for (const v of airFamily.profileValidators) {
    assert.equal(typeof v, "function");
  }
});

test("airFamily.validateBody is a pass-through (real validation lives in verifyAirBody)", () => {
  // The manifest's body validator is intentionally permissive — see body-validator.ts
  // for the rationale. Structural body validation continues to live in
  // verify-single.ts and is invoked separately by callers.
  const r = airFamily.validateBody({ event_type: "dpia.completed" });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.deepEqual(r.value, { event_type: "dpia.completed" });
  }
});

test("airFamily.walkParents returns [] (AIR has no lineage walker)", () => {
  assert.deepEqual([...airFamily.walkParents({ event_type: "dpia.completed" })], []);
});

test("airFamily exposes generateKeypair + signCanonical (Ed25519 pre-binding)", () => {
  assert.equal(typeof airFamily.generateKeypair, "function");
  assert.equal(typeof airFamily.signCanonical, "function");
});

test("airFamily declares continuity helpers (continuity: true)", () => {
  assert.equal(typeof airFamily.mintContinuity, "function");
  assert.equal(typeof airFamily.verifyContinuity, "function");
});

test("airFamily.compose is wired to composeAir (Phase 4B Task 3 single-receipt warnings)", () => {
  assert.equal(typeof airFamily.compose, "function");
});
