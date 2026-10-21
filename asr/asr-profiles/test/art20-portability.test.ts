/**
 * Tests for the `subject_rights.art20.portability` profile validator (ASR §5.5).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ART20_PORTABILITY_FORMATS,
  ART20_PORTABILITY_PROFILE_ID,
  validateArt20Portability,
  validateArt20PortabilityProfile,
} from "../src/art20-portability.ts";
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

test("art20: request.fulfilled with portability_format=json passes", () => {
  assert.deepEqual(
    validateArt20Portability(fulfilled({ portability_format: "json" })).errors,
    [],
  );
});

test("art20: every closed-enum format value passes (except other-without-detail)", () => {
  for (const fmt of ART20_PORTABILITY_FORMATS) {
    if (fmt === "other") continue;
    assert.deepEqual(
      validateArt20Portability(fulfilled({ portability_format: fmt })).errors,
      [],
      `format ${fmt} should pass`,
    );
  }
});

test("art20: request.fulfilled missing portability_format rejected", () => {
  const r = validateArt20Portability(fulfilled());
  assert.deepEqual(r.errors, [
    "subject_rights.art20.portability.portability_format.invalid",
  ]);
});

test("art20: request.fulfilled with unknown format value rejected", () => {
  const r = validateArt20Portability(
    fulfilled({ portability_format: "yaml" }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art20.portability.portability_format.invalid",
  ]);
});

test("art20: format=other without detail rejected", () => {
  const r = validateArt20Portability(
    fulfilled({ portability_format: "other" }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art20.portability.portability_format_detail.required",
  ]);
});

test("art20: format=other with non-empty detail passes", () => {
  const r = validateArt20Portability(
    fulfilled({
      portability_format: "other",
      portability_format_detail: "Custom NDJSON-with-schema",
    }),
  );
  assert.deepEqual(r.errors, []);
});

test("art20: format=other with empty detail rejected", () => {
  const r = validateArt20Portability(
    fulfilled({ portability_format: "other", portability_format_detail: "" }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art20.portability.portability_format_detail.required",
  ]);
});

test("art20: arr_receipt_id on fulfilled is forbidden", () => {
  const r = validateArt20Portability(
    fulfilled({ portability_format: "csv", arr_receipt_id: H("c") }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art20.portability.arr_receipt_id.forbidden",
  ]);
});

test("art20: missing format + arr_receipt_id present flags both", () => {
  const r = validateArt20Portability(fulfilled({ arr_receipt_id: H("d") }));
  assert.equal(r.errors.length, 2);
});

test("art20: lifecycle pass (received)", () => {
  assert.deepEqual(validateArt20Portability(received()).errors, []);
});

test("art20: lifecycle pass (identity_verified)", () => {
  assert.deepEqual(validateArt20Portability(identityVerified()).errors, []);
});

test("art20: lifecycle pass (scope_clarified)", () => {
  assert.deepEqual(validateArt20Portability(scopeClarified()).errors, []);
});

test("art20: lifecycle pass (extended)", () => {
  assert.deepEqual(validateArt20Portability(extended()).errors, []);
});

test("art20: lifecycle pass (partially_honoured)", () => {
  assert.deepEqual(validateArt20Portability(partiallyHonoured()).errors, []);
});

test("art20: lifecycle pass (refused)", () => {
  assert.deepEqual(validateArt20Portability(refused()).errors, []);
});

test("art20: lifecycle pass (escalated)", () => {
  assert.deepEqual(validateArt20Portability(escalated()).errors, []);
});

test("art20: lifecycle pass (recipient_notified)", () => {
  assert.deepEqual(validateArt20Portability(recipientNotified()).errors, []);
});

test("art20: adapter returns ok=true on valid fulfilled", () => {
  const entry = validateArt20PortabilityProfile(
    {} as never,
    fulfilled({ portability_format: "fhir" }),
    {},
  );
  assert.equal(entry.profile_id, ART20_PORTABILITY_PROFILE_ID);
  assert.equal(entry.ok, true);
});

test("art20: adapter surfaces invalid format code", () => {
  const entry = validateArt20PortabilityProfile({} as never, fulfilled(), {});
  assert.equal(entry.ok, false);
  assert.equal(
    entry.reason,
    "subject_rights.art20.portability.portability_format.invalid",
  );
});

test("art20: profile id constant matches spec", () => {
  assert.equal(
    ART20_PORTABILITY_PROFILE_ID,
    "subject_rights.art20.portability",
  );
});

test("art20: format enum count matches spec (7 values)", () => {
  assert.equal(ART20_PORTABILITY_FORMATS.length, 7);
});
