/**
 * Tests for the `subject_rights.art17.erasure_request` profile validator
 * (ASR §5.3, D10-ASR-3).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ART17_ERASURE_REQUEST_PROFILE_ID,
  validateArt17ErasureRequest,
  validateArt17ErasureRequestProfile,
} from "../src/art17-erasure-request.ts";
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

const ARR_ID = "arr_01HABCDEFGHJKMNPQRSTUVWXYZ";

test("art17: request.fulfilled with arr_receipt_id passes", () => {
  const r = validateArt17ErasureRequest(
    fulfilled({ arr_receipt_id: ARR_ID }),
  );
  assert.deepEqual(r.errors, []);
});

test("art17: request.fulfilled missing arr_receipt_id is HARD invalid", () => {
  const r = validateArt17ErasureRequest(fulfilled());
  assert.deepEqual(r.errors, [
    "subject_rights.art17.erasure_request.arr_receipt_id.missing",
  ]);
});

test("art17: request.fulfilled with null arr_receipt_id is HARD invalid", () => {
  const r = validateArt17ErasureRequest(fulfilled({ arr_receipt_id: null }));
  assert.deepEqual(r.errors, [
    "subject_rights.art17.erasure_request.arr_receipt_id.missing",
  ]);
});

test("art17: request.fulfilled with empty arr_receipt_id is HARD invalid", () => {
  const r = validateArt17ErasureRequest(fulfilled({ arr_receipt_id: "" }));
  assert.deepEqual(r.errors, [
    "subject_rights.art17.erasure_request.arr_receipt_id.missing",
  ]);
});

test("art17: request.fulfilled with portability_format set is forbidden", () => {
  const r = validateArt17ErasureRequest(
    fulfilled({ arr_receipt_id: ARR_ID, portability_format: "json" }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art17.erasure_request.portability_format.forbidden",
  ]);
});

test("art17: missing arr + present portability flags both", () => {
  const r = validateArt17ErasureRequest(
    fulfilled({ portability_format: "json" }),
  );
  assert.equal(r.errors.length, 2);
});

test("art17: lifecycle pass (received) — no arr requirement off fulfilled", () => {
  assert.deepEqual(validateArt17ErasureRequest(received()).errors, []);
});

test("art17: lifecycle pass (identity_verified)", () => {
  assert.deepEqual(validateArt17ErasureRequest(identityVerified()).errors, []);
});

test("art17: lifecycle pass (scope_clarified)", () => {
  assert.deepEqual(validateArt17ErasureRequest(scopeClarified()).errors, []);
});

test("art17: lifecycle pass (extended)", () => {
  assert.deepEqual(validateArt17ErasureRequest(extended()).errors, []);
});

test("art17: lifecycle pass (partially_honoured)", () => {
  assert.deepEqual(validateArt17ErasureRequest(partiallyHonoured()).errors, []);
});

test("art17: lifecycle pass (refused)", () => {
  assert.deepEqual(validateArt17ErasureRequest(refused()).errors, []);
});

test("art17: lifecycle pass (escalated)", () => {
  assert.deepEqual(validateArt17ErasureRequest(escalated()).errors, []);
});

test("art17: lifecycle pass (recipient_notified)", () => {
  assert.deepEqual(
    validateArt17ErasureRequest(recipientNotified()).errors,
    [],
  );
});

test("art17: adapter returns ok=true on linked fulfilled", () => {
  const entry = validateArt17ErasureRequestProfile(
    {} as never,
    fulfilled({ arr_receipt_id: ARR_ID }),
    {},
  );
  assert.equal(entry.profile_id, ART17_ERASURE_REQUEST_PROFILE_ID);
  assert.equal(entry.ok, true);
});

test("art17: adapter surfaces missing link code", () => {
  const entry = validateArt17ErasureRequestProfile(
    {} as never,
    fulfilled(),
    {},
  );
  assert.equal(entry.ok, false);
  assert.equal(
    entry.reason,
    "subject_rights.art17.erasure_request.arr_receipt_id.missing",
  );
});

test("art17: profile id constant matches spec", () => {
  assert.equal(
    ART17_ERASURE_REQUEST_PROFILE_ID,
    "subject_rights.art17.erasure_request",
  );
});

test("art17: arr_receipt_id may be ULID-shaped (no shape regex enforced)", () => {
  const r = validateArt17ErasureRequest(
    fulfilled({ arr_receipt_id: "01HKZ0000000000000000000XX" }),
  );
  assert.deepEqual(r.errors, []);
});

test("art17: arr_receipt_id may be sha256-shaped (no shape regex enforced)", () => {
  const r = validateArt17ErasureRequest(
    fulfilled({ arr_receipt_id: H("d") }),
  );
  assert.deepEqual(r.errors, []);
});
