/**
 * Tests for the `atokrFamily` manifest (Task 4 — subject-presence + family).
 *
 * Coverage:
 *   F1 — chip 14, status_list_slot 13, ar.tokenization.v1, continuity true,
 *        free TSA path, must-be-present subject_presence.
 *   F2 — subject_presence field is "must-be-present".
 *   F3 — checkSubjectPresence: valid sha256:<hex> subject passes.
 *   F4 — checkSubjectPresence: null subject fails with reason "subject_missing".
 *   F5 — 5 profiles registered with correct IDs.
 *   F6 — TSA mandate — all profiles return "optional" (all OPTIONAL per spec §5).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { atokrFamily } from "../src/family.ts";

const VALID_SHA = "sha256:" + "a".repeat(64);

test("atokrFamily declares chip 14, slot 13, ar.tokenization.v1, continuity true, free TSA path", () => {
  assert.equal(atokrFamily.meta.acronym, "ATokR");
  assert.equal(atokrFamily.meta.name, "Anchored Tokenization Receipts");
  assert.equal(atokrFamily.meta.chip, 14);
  assert.equal(atokrFamily.meta.status_list_slot, 13);
  assert.equal(atokrFamily.meta.tsa_upgrade_path, "free");
  assert.equal(atokrFamily.meta.continuity, true);
  assert.deepEqual([...atokrFamily.meta.claim_types], ["ar.tokenization.v1"]);
});

test("atokrFamily subject_presence is must-be-present", () => {
  assert.equal(atokrFamily.meta.subject_presence, "must-be-present");
});

test("atokrFamily.checkSubjectPresence — valid sha256:<hex> passes", () => {
  assert.deepEqual(
    atokrFamily.checkSubjectPresence(VALID_SHA, {}),
    { ok: true },
  );
});

test("atokrFamily.checkSubjectPresence — null subject fails with reason subject_missing", () => {
  assert.deepEqual(
    atokrFamily.checkSubjectPresence(null, {}),
    { ok: false, reason: "subject_missing" },
  );
});

test("atokrFamily registers all 5 v1 profiles", () => {
  assert.equal(atokrFamily.profileIds.length, 5);
  assert.equal(atokrFamily.hasProfile("tokenization.gdpr.art32"), true);
  assert.equal(atokrFamily.hasProfile("tokenization.gdpr.art4_5"), true);
  assert.equal(atokrFamily.hasProfile("tokenization.pci.dss_v4"), true);
  assert.equal(atokrFamily.hasProfile("tokenization.eudi.wallet_arf"), true);
  assert.equal(atokrFamily.hasProfile("tokenization.sector.health"), true);
  assert.equal(atokrFamily.hasProfile("tokenization.unknown"), false);
});

test("atokrFamily TSA mandate — all profiles are optional (all OPTIONAL per spec §5)", () => {
  assert.equal(atokrFamily.tsaMandateLevel("tokenization.gdpr.art32"), "optional");
  assert.equal(atokrFamily.tsaMandateLevel("tokenization.gdpr.art4_5"), "optional");
  assert.equal(atokrFamily.tsaMandateLevel("tokenization.pci.dss_v4"), "optional");
  assert.equal(atokrFamily.tsaMandateLevel("tokenization.eudi.wallet_arf"), "optional");
  assert.equal(atokrFamily.tsaMandateLevel("tokenization.sector.health"), "optional");
});
