/**
 * Tests for the `subject_rights.art18.restriction` profile validator (ASR §5.4).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ART18_RESTRICTION_PROFILE_ID,
  ART18_RESTRICTION_REASONS,
  validateArt18Restriction,
  validateArt18RestrictionProfile,
} from "../src/art18-restriction.ts";
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

const REASON_A = "art18_1_a_accuracy_contested";

test("art18: request.fulfilled with reason 1(a) passes", () => {
  assert.deepEqual(
    validateArt18Restriction(
      fulfilled({ restriction_reason_code: REASON_A }),
    ).errors,
    [],
  );
});

test("art18: request.fulfilled with each enum value passes (1a,1b,1c,1d)", () => {
  for (const code of ART18_RESTRICTION_REASONS) {
    assert.deepEqual(
      validateArt18Restriction(
        fulfilled({ restriction_reason_code: code }),
      ).errors,
      [],
      `reason ${code} should pass`,
    );
  }
});

test("art18: request.fulfilled missing reason code rejected", () => {
  const r = validateArt18Restriction(fulfilled());
  assert.deepEqual(r.errors, [
    "subject_rights.art18.restriction.restriction_reason_code.invalid",
  ]);
});

test("art18: request.fulfilled with unknown reason code rejected", () => {
  const r = validateArt18Restriction(
    fulfilled({ restriction_reason_code: "art18_1_z_not_a_thing" }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art18.restriction.restriction_reason_code.invalid",
  ]);
});

test("art18: arr_receipt_id on fulfilled is forbidden", () => {
  const r = validateArt18Restriction(
    fulfilled({
      restriction_reason_code: REASON_A,
      arr_receipt_id: H("a"),
    }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art18.restriction.arr_receipt_id.forbidden",
  ]);
});

test("art18: portability_format on fulfilled is forbidden", () => {
  const r = validateArt18Restriction(
    fulfilled({
      restriction_reason_code: REASON_A,
      portability_format: "json",
    }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art18.restriction.portability_format.forbidden",
  ]);
});

test("art18: multiple violations flagged together", () => {
  const r = validateArt18Restriction(
    fulfilled({ arr_receipt_id: H("b"), portability_format: "csv" }),
  );
  assert.equal(r.errors.length, 3);
});

test("art18: lifecycle pass (received)", () => {
  assert.deepEqual(validateArt18Restriction(received()).errors, []);
});

test("art18: lifecycle pass (identity_verified)", () => {
  assert.deepEqual(validateArt18Restriction(identityVerified()).errors, []);
});

test("art18: lifecycle pass (scope_clarified)", () => {
  assert.deepEqual(validateArt18Restriction(scopeClarified()).errors, []);
});

test("art18: lifecycle pass (extended)", () => {
  assert.deepEqual(validateArt18Restriction(extended()).errors, []);
});

test("art18: lifecycle pass (partially_honoured)", () => {
  assert.deepEqual(validateArt18Restriction(partiallyHonoured()).errors, []);
});

test("art18: lifecycle pass (refused)", () => {
  assert.deepEqual(validateArt18Restriction(refused()).errors, []);
});

test("art18: lifecycle pass (escalated)", () => {
  assert.deepEqual(validateArt18Restriction(escalated()).errors, []);
});

test("art18: lifecycle pass (recipient_notified)", () => {
  assert.deepEqual(validateArt18Restriction(recipientNotified()).errors, []);
});

test("art18: adapter returns ok=true on valid fulfilled", () => {
  const entry = validateArt18RestrictionProfile(
    {} as never,
    fulfilled({ restriction_reason_code: REASON_A }),
    {},
  );
  assert.equal(entry.profile_id, ART18_RESTRICTION_PROFILE_ID);
  assert.equal(entry.ok, true);
});

test("art18: adapter surfaces invalid reason code", () => {
  const entry = validateArt18RestrictionProfile({} as never, fulfilled(), {});
  assert.equal(entry.ok, false);
  assert.equal(
    entry.reason,
    "subject_rights.art18.restriction.restriction_reason_code.invalid",
  );
});

test("art18: profile id constant matches spec", () => {
  assert.equal(
    ART18_RESTRICTION_PROFILE_ID,
    "subject_rights.art18.restriction",
  );
});

test("art18: reason enum count matches spec (4 values)", () => {
  assert.equal(ART18_RESTRICTION_REASONS.length, 4);
});
