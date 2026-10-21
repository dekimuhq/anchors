/**
 * Tests for the `subject_rights.art21.objection` profile validator (ASR §5.6).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ART21_OBJECTION_PROFILE_ID,
  ART21_OBJECTION_SCOPES,
  validateArt21Objection,
  validateArt21ObjectionProfile,
} from "../src/art21-objection.ts";
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

test("art21: fulfilled with direct_marketing scope passes (no balancing test required)", () => {
  assert.deepEqual(
    validateArt21Objection(
      fulfilled({ objection_scope: "art21_1_direct_marketing" }),
    ).errors,
    [],
  );
});

test("art21: fulfilled with research scope passes (no balancing test required)", () => {
  assert.deepEqual(
    validateArt21Objection(
      fulfilled({ objection_scope: "art21_6_research" }),
    ).errors,
    [],
  );
});

test("art21: fulfilled with general_legitimate_interest requires balancing_test_hash", () => {
  const r = validateArt21Objection(
    fulfilled({ objection_scope: "art21_1_general_legitimate_interest" }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art21.objection.balancing_test_hash.required",
  ]);
});

test("art21: general_legitimate_interest with non-empty balancing_test_hash passes", () => {
  const r = validateArt21Objection(
    fulfilled({
      objection_scope: "art21_1_general_legitimate_interest",
      balancing_test_hash: H("b"),
    }),
  );
  assert.deepEqual(r.errors, []);
});

test("art21: general_legitimate_interest with empty balancing_test_hash rejected", () => {
  const r = validateArt21Objection(
    fulfilled({
      objection_scope: "art21_1_general_legitimate_interest",
      balancing_test_hash: "",
    }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art21.objection.balancing_test_hash.required",
  ]);
});

test("art21: fulfilled with unknown scope rejected", () => {
  const r = validateArt21Objection(
    fulfilled({ objection_scope: "art21_99_not_a_thing" }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art21.objection.objection_scope.invalid",
  ]);
});

test("art21: fulfilled with missing scope rejected", () => {
  const r = validateArt21Objection(fulfilled());
  assert.deepEqual(r.errors, [
    "subject_rights.art21.objection.objection_scope.invalid",
  ]);
});

test("art21: every scope enum value (with balancing where required) passes", () => {
  for (const scope of ART21_OBJECTION_SCOPES) {
    const overrides: Record<string, string> = { objection_scope: scope };
    if (scope === "art21_1_general_legitimate_interest") {
      overrides["balancing_test_hash"] = H("c");
    }
    assert.deepEqual(
      validateArt21Objection(fulfilled(overrides as never)).errors,
      [],
      `scope ${scope} should pass`,
    );
  }
});

test("art21: arr_receipt_id on fulfilled is forbidden", () => {
  const r = validateArt21Objection(
    fulfilled({
      objection_scope: "art21_1_direct_marketing",
      arr_receipt_id: H("a"),
    }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art21.objection.arr_receipt_id.forbidden",
  ]);
});

test("art21: portability_format on fulfilled is forbidden", () => {
  const r = validateArt21Objection(
    fulfilled({
      objection_scope: "art21_6_research",
      portability_format: "json",
    }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art21.objection.portability_format.forbidden",
  ]);
});

test("art21: missing scope + arr_receipt_id present flags both", () => {
  const r = validateArt21Objection(fulfilled({ arr_receipt_id: H("d") }));
  assert.equal(r.errors.length, 2);
});

test("art21: lifecycle pass (received)", () => {
  assert.deepEqual(validateArt21Objection(received()).errors, []);
});

test("art21: lifecycle pass (identity_verified)", () => {
  assert.deepEqual(validateArt21Objection(identityVerified()).errors, []);
});

test("art21: lifecycle pass (scope_clarified)", () => {
  assert.deepEqual(validateArt21Objection(scopeClarified()).errors, []);
});

test("art21: lifecycle pass (extended)", () => {
  assert.deepEqual(validateArt21Objection(extended()).errors, []);
});

test("art21: lifecycle pass (partially_honoured)", () => {
  assert.deepEqual(validateArt21Objection(partiallyHonoured()).errors, []);
});

test("art21: lifecycle pass (refused)", () => {
  assert.deepEqual(validateArt21Objection(refused()).errors, []);
});

test("art21: lifecycle pass (escalated)", () => {
  assert.deepEqual(validateArt21Objection(escalated()).errors, []);
});

test("art21: lifecycle pass (recipient_notified)", () => {
  assert.deepEqual(validateArt21Objection(recipientNotified()).errors, []);
});

test("art21: adapter returns ok=true on valid direct_marketing", () => {
  const entry = validateArt21ObjectionProfile(
    {} as never,
    fulfilled({ objection_scope: "art21_1_direct_marketing" }),
    {},
  );
  assert.equal(entry.profile_id, ART21_OBJECTION_PROFILE_ID);
  assert.equal(entry.ok, true);
});

test("art21: adapter surfaces missing balancing_test_hash", () => {
  const entry = validateArt21ObjectionProfile(
    {} as never,
    fulfilled({ objection_scope: "art21_1_general_legitimate_interest" }),
    {},
  );
  assert.equal(entry.ok, false);
  assert.equal(
    entry.reason,
    "subject_rights.art21.objection.balancing_test_hash.required",
  );
});

test("art21: profile id constant matches spec", () => {
  assert.equal(ART21_OBJECTION_PROFILE_ID, "subject_rights.art21.objection");
});

test("art21: scope enum count matches spec (3 values)", () => {
  assert.equal(ART21_OBJECTION_SCOPES.length, 3);
});
