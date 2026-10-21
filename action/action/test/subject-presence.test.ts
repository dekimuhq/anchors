/**
 * Tests for checkActionSubjectPresence (AActR: subject MUST be null).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { checkActionSubjectPresence } from "../src/subject-presence.ts";

test("SP1: null subject → ok", () => {
  assert.deepEqual(checkActionSubjectPresence({ subject: null }), { ok: true });
});

test("SP2: string subject → subject_must_be_null", () => {
  const r = checkActionSubjectPresence({ subject: "sha256:" + "a".repeat(64) });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

test("SP3: empty string subject → subject_must_be_null", () => {
  const r = checkActionSubjectPresence({ subject: "" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

test("SP4: object subject → subject_must_be_null", () => {
  const r = checkActionSubjectPresence({ subject: {} });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

test("SP5: number subject → subject_must_be_null", () => {
  const r = checkActionSubjectPresence({ subject: 0 });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

test("SP6: undefined subject → subject_must_be_null (only null passes)", () => {
  const r = checkActionSubjectPresence({ subject: undefined });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});
