/**
 * Tests for the AGR family manifest (defineFamily wiring). Chip 17, ar.guard.v1.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { guardFamily } from "../src/family.ts";

const HEX64 = "a".repeat(64);
const HEX64B = "b".repeat(64);

test("F1: acronym is AGR", () => {
  assert.equal(guardFamily.meta.acronym, "AGR");
});

test("F2: name is Anchored Guard Verdicts", () => {
  assert.equal(guardFamily.meta.name, "Anchored Guard Verdicts");
});

test("F3: owns ar.guard.v1 claim_type", () => {
  assert.deepEqual([...guardFamily.meta.claim_types], ["ar.guard.v1"]);
});

test("F4: chip is 17", () => {
  assert.equal(guardFamily.meta.chip, 17);
});

test("F5: status_list_slot is null (non-revocable)", () => {
  assert.equal(guardFamily.meta.status_list_slot, null);
});

test("F6: subject_presence is must-be-null", () => {
  assert.equal(guardFamily.meta.subject_presence, "must-be-null");
});

test("F7: tsa_upgrade_path is free", () => {
  assert.equal(guardFamily.meta.tsa_upgrade_path, "free");
});

test("F8: continuity is false (single-receipt, no chain)", () => {
  assert.equal(guardFamily.meta.continuity, false);
});

test("F9: spec_path points at the AGR design doc", () => {
  assert.match(guardFamily.meta.spec_path, /^https:\/\/github\.com\/dekimuhq\/anchors-spec\/tree\/main\/guard$/);
});

test("F10: guard.input profile is registered", () => {
  assert.equal(guardFamily.hasProfile("guard.input"), true);
});

test("F11: only guard.input profile registered, no extras", () => {
  assert.deepEqual([...guardFamily.profileIds].sort(), ["guard.input"]);
});

test("F12: validateBody accepts a valid guard.input body", () => {
  const r = guardFamily.validateBody({
    profile: "guard.input",
    ruleset_id: "ruleset-default",
    ruleset_hash: HEX64,
    ruleset_version: "v1.0.0",
    content_commit: HEX64B,
    decision: "pass",
    matched_rules: [],
    detector: { engine: "deterministic", name: "guard-engine", version: "1.0.0" },
    screened_at: "2026-06-20T10:00:00Z",
  });
  assert.equal(r.ok, true);
});

test("F13: validateBody rejects a non-object with body.not_object reason", () => {
  const r = guardFamily.validateBody("nope");
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "body.not_object");
});
