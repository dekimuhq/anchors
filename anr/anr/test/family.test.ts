/**
 * Tests for the `anrFamily` manifest (Phase 2 Task 2.1).
 *
 * Exercises the surface most likely to drift during migration: identity
 * invariants, the per-event subject-presence callback, the per-profile TSA
 * mandate matrix, and the manifest's pass-through body validator. Profile
 * registration is checked via `hasProfile` / `profileIds`. The factory's
 * `verifyReceipt` / `mintV2` surfaces are exercised through the existing
 * `envelope-v2.ts` and `mint-v2.ts` wrappers in their own test suites.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { anrFamily } from "../src/family.ts";

test("anrFamily declares chip 10, status_list_slot 4, ar.notice.v1, continuity, free TSA path", () => {
  assert.equal(anrFamily.meta.acronym, "ANR");
  assert.equal(anrFamily.meta.name, "Anchored Notice Receipts");
  assert.equal(anrFamily.meta.chip, 10);
  assert.equal(anrFamily.meta.status_list_slot, 4);
  assert.equal(anrFamily.meta.subject_presence, "either");
  assert.equal(anrFamily.meta.tsa_upgrade_path, "free");
  assert.equal(anrFamily.meta.continuity, true);
  assert.equal(anrFamily.meta.batch, false);
  assert.equal(anrFamily.meta.predicate_recommended, false);
  assert.deepEqual([...anrFamily.meta.claim_types], ["ar.notice.v1"]);
});

test("anrFamily.isOwnedClaimType only accepts ar.notice.v1", () => {
  assert.equal(anrFamily.isOwnedClaimType("ar.notice.v1"), true);
  assert.equal(anrFamily.isOwnedClaimType("ar.provenance.v1"), false);
  assert.equal(anrFamily.isOwnedClaimType("ar.consent.v1"), false);
  assert.equal(anrFamily.isOwnedClaimType("ar.lineage.v1"), false);
  assert.equal(anrFamily.isOwnedClaimType("ar.notice.v2"), false);
});

test("anrFamily.checkSubjectPresence — notice.acknowledged MUST be sha256:<hex>", () => {
  const sha = "sha256:" + "a".repeat(64);
  const body = { event_type: "notice.acknowledged" };
  assert.deepEqual(anrFamily.checkSubjectPresence(sha, body), { ok: true });
  assert.deepEqual(
    anrFamily.checkSubjectPresence(null, body),
    { ok: false, reason: "subject_missing" },
  );
  assert.deepEqual(
    anrFamily.checkSubjectPresence("nothex", body),
    { ok: false, reason: "subject_invalid_form" },
  );
});

test("anrFamily.checkSubjectPresence — non-ack events accept sha256 OR null", () => {
  const sha = "sha256:" + "b".repeat(64);
  for (const event_type of [
    "notice.presented",
    "notice.re_presented",
    "notice.withdrawn",
    "notice.translated",
    "notice.joint_controller_essence",
  ]) {
    const body = { event_type };
    assert.deepEqual(
      anrFamily.checkSubjectPresence(null, body),
      { ok: true },
      `null subject MUST be accepted for ${event_type}`,
    );
    assert.deepEqual(
      anrFamily.checkSubjectPresence(sha, body),
      { ok: true },
      `sha256 subject MUST be accepted for ${event_type}`,
    );
    assert.deepEqual(
      anrFamily.checkSubjectPresence("bogus", body),
      { ok: false, reason: "subject_invalid_form" },
      `malformed subject MUST be rejected for ${event_type}`,
    );
  }
});

test("anrFamily.tsaMandateLevel — AI Act Art. 50 is mandatory, all other v1 profiles recommended", () => {
  assert.equal(
    anrFamily.tsaMandateLevel("notice.aiact.art50_transparency"),
    "mandatory",
  );
  assert.equal(
    anrFamily.tsaMandateLevel("notice.art13.collected_direct"),
    "recommended",
  );
  assert.equal(
    anrFamily.tsaMandateLevel("notice.art14.collected_indirect"),
    "recommended",
  );
  assert.equal(
    anrFamily.tsaMandateLevel("notice.art26.joint_controller_essence"),
    "recommended",
  );
  assert.equal(
    anrFamily.tsaMandateLevel("notice.layered_transparency"),
    "recommended",
  );
});

test("anrFamily.tsaMandateLevel returns optional for unknown profile ids", () => {
  assert.equal(anrFamily.tsaMandateLevel("notice.unknown"), "optional");
  assert.equal(anrFamily.tsaMandateLevel(""), "optional");
});

test("anrFamily registers all 5 v1 profiles in spec order", () => {
  assert.deepEqual([...anrFamily.profileIds], [
    "notice.art13.collected_direct",
    "notice.art14.collected_indirect",
    "notice.art26.joint_controller_essence",
    "notice.layered_transparency",
    "notice.aiact.art50_transparency",
  ]);
  for (const id of anrFamily.profileIds) {
    assert.equal(anrFamily.hasProfile(id), true);
  }
  assert.equal(anrFamily.hasProfile("notice.unknown"), false);
  assert.equal(anrFamily.profileValidators.length, 5);
  for (const v of anrFamily.profileValidators) {
    assert.equal(typeof v, "function");
  }
});

test("anrFamily.validateBody is a pass-through (real validation lives in verifyAnrBody)", () => {
  // The manifest's body validator is intentionally permissive — see body-validator.ts
  // for the rationale. Structural body validation continues to live in
  // verify-single.ts and is invoked separately by callers.
  const r = anrFamily.validateBody({ event_type: "notice.presented" });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.deepEqual(r.value, { event_type: "notice.presented" });
  }
});

test("anrFamily.walkParents returns [] (ANR has no lineage walker)", () => {
  assert.deepEqual([...anrFamily.walkParents({ event_type: "notice.presented" })], []);
});

test("anrFamily exposes generateKeypair + signCanonical (Ed25519 pre-binding)", () => {
  assert.equal(typeof anrFamily.generateKeypair, "function");
  assert.equal(typeof anrFamily.signCanonical, "function");
});

test("anrFamily declares continuity helpers (continuity: true)", () => {
  assert.equal(typeof anrFamily.mintContinuity, "function");
  assert.equal(typeof anrFamily.verifyContinuity, "function");
});

test("anrFamily.compose is wired to composeAnr (Phase 4D — lang_jurisdiction_mismatch + base_unresolvable)", () => {
  assert.equal(typeof anrFamily.compose, "function");
});
