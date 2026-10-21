/**
 * Tests for the `subject_rights.art16.rectification` profile validator (ASR §5.2).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ART16_RECTIFICATION_PROFILE_ID,
  validateArt16Rectification,
  validateArt16RectificationProfile,
} from "../src/art16-rectification.ts";
import {
  H,
  escalated,
  extended,
  fulfilled,
  identityVerified,
  partiallyHonoured,
  received,
  recipientNotified,
  refused,
  scopeClarified,
} from "./_helpers/bodies.ts";

test("art16: request.fulfilled with bare body passes", () => {
  assert.deepEqual(validateArt16Rectification(fulfilled()).errors, []);
});

test("art16: lifecycle pass (received)", () => {
  assert.deepEqual(validateArt16Rectification(received()).errors, []);
});

test("art16: lifecycle pass (identity_verified)", () => {
  assert.deepEqual(validateArt16Rectification(identityVerified()).errors, []);
});

test("art16: lifecycle pass (scope_clarified)", () => {
  assert.deepEqual(validateArt16Rectification(scopeClarified()).errors, []);
});

test("art16: lifecycle pass (extended)", () => {
  assert.deepEqual(validateArt16Rectification(extended()).errors, []);
});

test("art16: lifecycle pass (partially_honoured)", () => {
  assert.deepEqual(validateArt16Rectification(partiallyHonoured()).errors, []);
});

test("art16: lifecycle pass (refused)", () => {
  assert.deepEqual(validateArt16Rectification(refused()).errors, []);
});

test("art16: lifecycle pass (escalated)", () => {
  assert.deepEqual(validateArt16Rectification(escalated()).errors, []);
});

test("art16: lifecycle pass (recipient_notified)", () => {
  assert.deepEqual(validateArt16Rectification(recipientNotified()).errors, []);
});

test("art16: arr_receipt_id on fulfilled is forbidden", () => {
  const r = validateArt16Rectification(fulfilled({ arr_receipt_id: H("b") }));
  assert.deepEqual(r.errors, [
    "subject_rights.art16.rectification.arr_receipt_id.forbidden",
  ]);
});

test("art16: portability_format on fulfilled is forbidden", () => {
  const r = validateArt16Rectification(fulfilled({ portability_format: "xml" }));
  assert.deepEqual(r.errors, [
    "subject_rights.art16.rectification.portability_format.forbidden",
  ]);
});

test("art16: both forbidden fields flagged together", () => {
  const r = validateArt16Rectification(
    fulfilled({ arr_receipt_id: H("c"), portability_format: "json" }),
  );
  assert.equal(r.errors.length, 2);
});

test("art16: null arr_receipt_id passes", () => {
  assert.deepEqual(
    validateArt16Rectification(fulfilled({ arr_receipt_id: null })).errors,
    [],
  );
});

test("art16: empty arr_receipt_id treated as absent", () => {
  assert.deepEqual(
    validateArt16Rectification(fulfilled({ arr_receipt_id: "" })).errors,
    [],
  );
});

test("art16: adapter returns ok=true on bare fulfilled", () => {
  const entry = validateArt16RectificationProfile({} as never, fulfilled(), {});
  assert.equal(entry.profile_id, ART16_RECTIFICATION_PROFILE_ID);
  assert.equal(entry.ok, true);
});

test("art16: adapter surfaces forbidden field code", () => {
  const entry = validateArt16RectificationProfile(
    {} as never,
    fulfilled({ portability_format: "csv" }),
    {},
  );
  assert.equal(entry.ok, false);
  assert.equal(
    entry.reason,
    "subject_rights.art16.rectification.portability_format.forbidden",
  );
});

test("art16: profile id constant matches spec", () => {
  assert.equal(
    ART16_RECTIFICATION_PROFILE_ID,
    "subject_rights.art16.rectification",
  );
});
