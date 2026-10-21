/**
 * Tests for the `subject_rights.art15.access` profile validator (ASR §5.1).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ART15_ACCESS_PROFILE_ID,
  validateArt15Access,
  validateArt15AccessProfile,
} from "../src/art15-access.ts";
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

test("art15: request.fulfilled with bare body passes", () => {
  const r = validateArt15Access(fulfilled());
  assert.deepEqual(r.errors, []);
});

test("art15: lifecycle events pass uniformly (received)", () => {
  assert.deepEqual(validateArt15Access(received()).errors, []);
});

test("art15: lifecycle events pass uniformly (identity_verified)", () => {
  assert.deepEqual(validateArt15Access(identityVerified()).errors, []);
});

test("art15: lifecycle events pass uniformly (scope_clarified)", () => {
  assert.deepEqual(validateArt15Access(scopeClarified()).errors, []);
});

test("art15: lifecycle events pass uniformly (extended)", () => {
  assert.deepEqual(validateArt15Access(extended()).errors, []);
});

test("art15: lifecycle events pass uniformly (partially_honoured)", () => {
  assert.deepEqual(validateArt15Access(partiallyHonoured()).errors, []);
});

test("art15: lifecycle events pass uniformly (refused)", () => {
  assert.deepEqual(validateArt15Access(refused()).errors, []);
});

test("art15: lifecycle events pass uniformly (escalated)", () => {
  assert.deepEqual(validateArt15Access(escalated()).errors, []);
});

test("art15: lifecycle events pass uniformly (recipient_notified)", () => {
  assert.deepEqual(validateArt15Access(recipientNotified()).errors, []);
});

test("art15: arr_receipt_id set on fulfilled is forbidden", () => {
  const r = validateArt15Access(fulfilled({ arr_receipt_id: H("a") }));
  assert.deepEqual(r.errors, [
    "subject_rights.art15.access.arr_receipt_id.forbidden",
  ]);
});

test("art15: portability_format set on fulfilled is forbidden", () => {
  const r = validateArt15Access(fulfilled({ portability_format: "json" }));
  assert.deepEqual(r.errors, [
    "subject_rights.art15.access.portability_format.forbidden",
  ]);
});

test("art15: both arr_receipt_id and portability_format flagged together", () => {
  const r = validateArt15Access(
    fulfilled({ arr_receipt_id: H("a"), portability_format: "csv" }),
  );
  assert.deepEqual(r.errors, [
    "subject_rights.art15.access.arr_receipt_id.forbidden",
    "subject_rights.art15.access.portability_format.forbidden",
  ]);
});

test("art15: null arr_receipt_id on fulfilled passes", () => {
  const r = validateArt15Access(fulfilled({ arr_receipt_id: null }));
  assert.deepEqual(r.errors, []);
});

test("art15: empty-string arr_receipt_id treated as absent", () => {
  const r = validateArt15Access(fulfilled({ arr_receipt_id: "" }));
  assert.deepEqual(r.errors, []);
});

test("art15: adapter returns ok=true on bare fulfilled", () => {
  const entry = validateArt15AccessProfile({} as never, fulfilled(), {});
  assert.equal(entry.profile_id, ART15_ACCESS_PROFILE_ID);
  assert.equal(entry.ok, true);
  assert.equal(entry.reason, undefined);
});

test("art15: adapter surfaces first error as reason", () => {
  const entry = validateArt15AccessProfile(
    {} as never,
    fulfilled({ arr_receipt_id: H("a") }),
    {},
  );
  assert.equal(entry.ok, false);
  assert.equal(
    entry.reason,
    "subject_rights.art15.access.arr_receipt_id.forbidden",
  );
});

test("art15: adapter shape includes profile_id even on success", () => {
  const entry = validateArt15AccessProfile({} as never, received(), {});
  assert.equal(entry.profile_id, ART15_ACCESS_PROFILE_ID);
  assert.equal(entry.ok, true);
});

test("art15: profile id constant matches spec", () => {
  assert.equal(ART15_ACCESS_PROFILE_ID, "subject_rights.art15.access");
});
