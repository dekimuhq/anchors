/**
 * Tests for the AQR family manifest (defineFamily wiring). Chip 16, ar.quality.v1.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { qualityFamily } from "../src/family.ts";

test("F1: acronym is AQR", () => {
  assert.equal(qualityFamily.meta.acronym, "AQR");
});

test("F2: name is Anchored Quality Receipts", () => {
  assert.equal(qualityFamily.meta.name, "Anchored Quality Receipts");
});

test("F3: owns ar.quality.v1 claim_type", () => {
  assert.deepEqual([...qualityFamily.meta.claim_types], ["ar.quality.v1"]);
});

test("F4: chip is 16", () => {
  assert.equal(qualityFamily.meta.chip, 16);
});

test("F5: status_list_slot is null (non-revocable)", () => {
  assert.equal(qualityFamily.meta.status_list_slot, null);
});

test("F6: subject_presence is must-be-null", () => {
  assert.equal(qualityFamily.meta.subject_presence, "must-be-null");
});

test("F7: tsa_upgrade_path is free", () => {
  assert.equal(qualityFamily.meta.tsa_upgrade_path, "free");
});

test("F8: continuity is false (single-receipt, no chain)", () => {
  assert.equal(qualityFamily.meta.continuity, false);
});

test("F9: spec_path points at the AQR design doc", () => {
  assert.match(qualityFamily.meta.spec_path, /^https:\/\/github\.com\/dekimuhq\/anchors-spec\/tree\/main\/quality$/);
});

test("F10: quality.output profile is registered", () => {
  assert.equal(qualityFamily.hasProfile("quality.output"), true);
});

test("F11: quality.release profile is registered", () => {
  assert.equal(qualityFamily.hasProfile("quality.release"), true);
});

test("F12: both profiles registered, no extras", () => {
  assert.deepEqual([...qualityFamily.profileIds].sort(), ["quality.output", "quality.release"]);
});

test("F13: validateBody accepts a valid output body", () => {
  const r = qualityFamily.validateBody({
    profile: "quality.output",
    suite_id: "suite-x",
    suite_hash: "sha256:" + "a".repeat(64),
    scorer: { kind: "deterministic" },
    result: { score: 0.9, threshold: 0.8, verdict: "pass", cases_total: 10, cases_passed: 9 },
    ran_at: "2026-06-19T10:00:00Z",
    output_commit: "sha256:" + "b".repeat(64),
  });
  assert.equal(r.ok, true);
});

test("F14: validateBody rejects a non-object with body.not_object reason", () => {
  const r = qualityFamily.validateBody("nope");
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "body.not_object");
});
