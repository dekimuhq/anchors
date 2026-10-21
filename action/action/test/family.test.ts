/**
 * Tests for the AActR family manifest (defineFamily wiring).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { actionFamily } from "../src/family.ts";
import { validBody } from "./_helpers/fixtures.ts";

test("F1: acronym is AActR", () => {
  assert.equal(actionFamily.meta.acronym, "AActR");
});

test("F2: name is Anchored Action Receipts", () => {
  assert.equal(actionFamily.meta.name, "Anchored Action Receipts");
});

test("F3: owns ar.action.v1 claim_type", () => {
  assert.deepEqual([...actionFamily.meta.claim_types], ["ar.action.v1"]);
});

test("F4: chip is 15", () => {
  assert.equal(actionFamily.meta.chip, 15);
});

test("F5: status_list_slot is null (non-consumer)", () => {
  assert.equal(actionFamily.meta.status_list_slot, null);
});

test("F6: subject_presence is must-be-null", () => {
  assert.equal(actionFamily.meta.subject_presence, "must-be-null");
});

test("F7: tsa_upgrade_path is free", () => {
  assert.equal(actionFamily.meta.tsa_upgrade_path, "free");
});

test("F8: continuity is false (single-receipt, no chain)", () => {
  assert.equal(actionFamily.meta.continuity, false);
});

test("F9: exposes a verifyReceipt method", () => {
  assert.equal(typeof actionFamily.verifyReceipt, "function");
});

test("F10: spec_path points at the AActR design doc", () => {
  assert.match(actionFamily.meta.spec_path, /^https:\/\/github\.com\/dekimuhq\/anchors-spec\/tree\/main\/action$/);
});

test("F11: validateBody accepts a valid body", () => {
  const r = actionFamily.validateBody(validBody());
  assert.equal(r.ok, true);
});

test("F12: validateBody rejects an invalid body with a reason", () => {
  const r = actionFamily.validateBody({ profile: "x" });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(typeof r.reason, "string");
});

test("F13: validateBody reason surfaces the first verify error", () => {
  const r = actionFamily.validateBody("nope");
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "body.not_object");
});

test("F14: does not emit batch claim_type", () => {
  assert.equal(actionFamily.meta.batch, false);
});
