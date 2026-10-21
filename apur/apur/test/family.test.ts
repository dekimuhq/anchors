/**
 * Tests for the `apurFamily` manifest.
 *
 * Coverage:
 *   F1 — chip 6, status_list_slot 10, ar.purpose.v1, continuity true, free TSA path.
 *   F2 — subject_presence field is "must-be-null".
 *   F3 — checkSubjectPresence: null subject passes.
 *   F4 — checkSubjectPresence: non-null subject fails.
 *   F5 — 4 profiles registered with correct IDs.
 *   F6 — TSA mandate — all profiles return "optional" (all OPTIONAL per spec §5).
 *   F7 — isOwnedClaimType returns true for ar.purpose.v1.
 *   F8 — isOwnedClaimType returns false for unknown type.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { apurFamily } from "../src/family.ts";

test("apurFamily declares chip 6, slot 10, ar.purpose.v1, continuity true, free TSA path", () => {
  assert.equal(apurFamily.meta.acronym, "APuR");
  assert.equal(apurFamily.meta.name, "Anchored Purpose Receipts");
  assert.equal(apurFamily.meta.chip, 6);
  assert.equal(apurFamily.meta.status_list_slot, 10);
  assert.equal(apurFamily.meta.tsa_upgrade_path, "free");
  assert.equal(apurFamily.meta.continuity, true);
  assert.deepEqual([...apurFamily.meta.claim_types], ["ar.purpose.v1"]);
});

test("apurFamily subject_presence is must-be-null", () => {
  assert.equal(apurFamily.meta.subject_presence, "must-be-null");
});

test("apurFamily.checkSubjectPresence — null subject passes", () => {
  assert.deepEqual(
    apurFamily.checkSubjectPresence(null, {}),
    { ok: true },
  );
});

test("apurFamily.checkSubjectPresence — non-null subject fails", () => {
  const result = apurFamily.checkSubjectPresence("sha256:" + "a".repeat(64), {});
  assert.equal(result.ok, false);
  assert.ok("reason" in result && typeof result.reason === "string");
});

test("apurFamily registers all 4 v1 profiles", () => {
  assert.equal(apurFamily.profileIds.length, 4);
  assert.equal(apurFamily.hasProfile("purpose.gdpr.art5"), true);
  assert.equal(apurFamily.hasProfile("purpose.gdpr.art6_4"), true);
  assert.equal(apurFamily.hasProfile("purpose.hipaa.minimum_necessary"), true);
  assert.equal(apurFamily.hasProfile("purpose.lgpd.art6"), true);
  assert.equal(apurFamily.hasProfile("purpose.unknown"), false);
});

test("apurFamily TSA mandate — all profiles are optional (all OPTIONAL per spec §5)", () => {
  assert.equal(apurFamily.tsaMandateLevel("purpose.gdpr.art5"), "optional");
  assert.equal(apurFamily.tsaMandateLevel("purpose.gdpr.art6_4"), "optional");
  assert.equal(apurFamily.tsaMandateLevel("purpose.hipaa.minimum_necessary"), "optional");
  assert.equal(apurFamily.tsaMandateLevel("purpose.lgpd.art6"), "optional");
});

test("apurFamily.isOwnedClaimType returns true for ar.purpose.v1", () => {
  assert.equal(apurFamily.isOwnedClaimType("ar.purpose.v1"), true);
});

test("apurFamily.isOwnedClaimType returns false for unknown type", () => {
  assert.equal(apurFamily.isOwnedClaimType("ar.unknown.v1"), false);
});
