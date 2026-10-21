/**
 * Tests for the `abrFamily` manifest (Phase 4C Task 1 — factory canary).
 *
 * Exercises the surface most likely to drift during migration: identity
 * invariants, the per-event subject-presence callback (stricter than ANR —
 * incident-level events are `null`-only, not "either"), the
 * (declarative-only) profile-keyed TSA mandate matrix, and the manifest's
 * pass-through body validator + profile registration. The factory's
 * `verifyReceipt` / `mintV2` surfaces are exercised through the existing
 * `envelope-v2.ts` and `mint-v2.ts` wrappers in their own test suites once
 * the Task 2 collapse lands.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { abrFamily } from "../src/family.ts";

test("abrFamily declares chip 11, status_list_slot 5, ar.breach.v1, continuity, free TSA path", () => {
  assert.equal(abrFamily.meta.acronym, "ABR");
  assert.equal(abrFamily.meta.name, "Anchored Breach Receipts");
  assert.equal(abrFamily.meta.chip, 11);
  assert.equal(abrFamily.meta.status_list_slot, 5);
  assert.equal(abrFamily.meta.subject_presence, "either");
  assert.equal(abrFamily.meta.tsa_upgrade_path, "free");
  assert.equal(abrFamily.meta.continuity, true);
  assert.equal(abrFamily.meta.batch, false);
  assert.equal(abrFamily.meta.predicate_recommended, false);
  assert.deepEqual([...abrFamily.meta.claim_types], ["ar.breach.v1"]);
});

test("abrFamily.isOwnedClaimType only accepts ar.breach.v1", () => {
  assert.equal(abrFamily.isOwnedClaimType("ar.breach.v1"), true);
  assert.equal(abrFamily.isOwnedClaimType("ar.notice.v1"), false);
  assert.equal(abrFamily.isOwnedClaimType("ar.impact.v1"), false);
  assert.equal(abrFamily.isOwnedClaimType("ar.consent.v1"), false);
  assert.equal(abrFamily.isOwnedClaimType("ar.breach.v2"), false);
});

test("abrFamily.checkSubjectPresence — incident-level events require subject: null", () => {
  for (const event_type of [
    "breach.detected",
    "breach.assessed",
    "breach.dpa_notified",
    "breach.dpa_delayed",
    "breach.subject_notification_exempted",
    "breach.contained",
    "breach.closed",
  ]) {
    const body = { event_type };
    assert.deepEqual(
      abrFamily.checkSubjectPresence(null, body),
      { ok: true },
      `null subject MUST be accepted for ${event_type}`,
    );
    assert.deepEqual(
      abrFamily.checkSubjectPresence("sha256:" + "a".repeat(64), body),
      { ok: false, reason: "subject_present" },
      `sha256 subject MUST be rejected for ${event_type}`,
    );
    assert.deepEqual(
      abrFamily.checkSubjectPresence("bogus", body),
      { ok: false, reason: "subject_present" },
      `arbitrary string MUST be rejected for ${event_type}`,
    );
  }
});

test("abrFamily.checkSubjectPresence — breach.subject_notified MUST be sha256", () => {
  const body = { event_type: "breach.subject_notified" };
  const sha = "sha256:" + "b".repeat(64);
  assert.deepEqual(
    abrFamily.checkSubjectPresence(sha, body),
    { ok: true },
    "sha256 subject MUST be accepted on breach.subject_notified",
  );
  assert.deepEqual(
    abrFamily.checkSubjectPresence(null, body),
    { ok: false, reason: "subject_missing" },
    "null subject MUST be rejected on breach.subject_notified",
  );
  assert.deepEqual(
    abrFamily.checkSubjectPresence("", body),
    { ok: false, reason: "subject_missing" },
    "empty subject MUST be rejected on breach.subject_notified",
  );
});

test("abrFamily.checkSubjectPresence — breach.subject_notified malformed subject rejects with subject_invalid_form", () => {
  const body = { event_type: "breach.subject_notified" };
  assert.deepEqual(
    abrFamily.checkSubjectPresence("nothex", body),
    { ok: false, reason: "subject_invalid_form" },
  );
  assert.deepEqual(
    abrFamily.checkSubjectPresence("sha256:zzzz", body),
    { ok: false, reason: "subject_invalid_form" },
  );
  assert.deepEqual(
    abrFamily.checkSubjectPresence("sha256:" + "A".repeat(64), body),
    { ok: false, reason: "subject_invalid_form" },
    "uppercase hex MUST be rejected (sha256:<lowercase-hex> form per v1.1 envelope §5.4)",
  );
});

test("abrFamily.tsaMandateLevel — all five v1 profiles are recommended (event-keyed matrix handled in wrapper)", () => {
  assert.equal(abrFamily.tsaMandateLevel("breach.gdpr.art33"), "recommended");
  assert.equal(abrFamily.tsaMandateLevel("breach.gdpr.art34"), "recommended");
  assert.equal(abrFamily.tsaMandateLevel("breach.nis2.art23"), "recommended");
  assert.equal(abrFamily.tsaMandateLevel("breach.dora.art19"), "recommended");
  assert.equal(
    abrFamily.tsaMandateLevel("breach.us_state.attorney_general"),
    "recommended",
  );
});

test("abrFamily.tsaMandateLevel returns optional for unknown profile ids", () => {
  assert.equal(abrFamily.tsaMandateLevel("breach.unknown"), "optional");
  assert.equal(abrFamily.tsaMandateLevel(""), "optional");
});

test("abrFamily registers all 5 v1 profiles in spec order", () => {
  assert.deepEqual([...abrFamily.profileIds], [
    "breach.gdpr.art33",
    "breach.gdpr.art34",
    "breach.nis2.art23",
    "breach.dora.art19",
    "breach.us_state.attorney_general",
  ]);
  for (const id of abrFamily.profileIds) {
    assert.equal(abrFamily.hasProfile(id), true);
  }
  assert.equal(abrFamily.hasProfile("breach.unknown"), false);
  assert.equal(abrFamily.profileValidators.length, 5);
  for (const v of abrFamily.profileValidators) {
    assert.equal(typeof v, "function");
  }
});

test("abrFamily.validateBody is a pass-through (real validation lives in verifyAbrBody)", () => {
  // The manifest's body validator is intentionally permissive — see body-validator.ts
  // for the rationale. Structural body validation continues to live in
  // verify-single.ts and is invoked separately by callers.
  const r = abrFamily.validateBody({ event_type: "breach.detected" });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.deepEqual(r.value, { event_type: "breach.detected" });
  }
});

test("abrFamily.walkParents returns [] (ABR has no lineage walker)", () => {
  assert.deepEqual([...abrFamily.walkParents({ event_type: "breach.detected" })], []);
});

test("abrFamily exposes generateKeypair + signCanonical (Ed25519 pre-binding)", () => {
  assert.equal(typeof abrFamily.generateKeypair, "function");
  assert.equal(typeof abrFamily.signCanonical, "function");
});

test("abrFamily declares continuity helpers (continuity: true)", () => {
  assert.equal(typeof abrFamily.mintContinuity, "function");
  assert.equal(typeof abrFamily.verifyContinuity, "function");
});

test("abrFamily.compose is wired to composeAbr (Phase 4C Task 3 — clock_skew_warning + notification_overdue)", () => {
  assert.equal(typeof abrFamily.compose, "function");
});
