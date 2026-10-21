/**
 * Subject-presence tests for ATokR — universal must-be-present rule.
 *
 * FAMILY-CONSISTENCY.md §3: ATokR is the simplest family member — every event
 * MUST carry `subject = "sha256:<hex>"`. No per-event split.
 *
 * Coverage:
 *   SP1 — valid sha256:<hex> subject               → ok.
 *   SP2 — null subject                             → subject_must_be_present.
 *   SP3 — empty string                             → subject_must_be_present.
 *   SP4 — non-sha256 string                        → subject_must_be_sha256.
 *   SP5 — uppercase hex (sha256:AABB...)           → subject_must_be_sha256.
 *   SP6 — wrong length hex (63 chars)              → subject_must_be_sha256.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { checkAtokrSubjectPresence } from "../src/subject-presence.ts";

const VALID_SHA = "sha256:" + "a".repeat(64);

test("atokr subject-presence: valid sha256:<hex> is accepted (SP1)", () => {
  const r = checkAtokrSubjectPresence({ subject: VALID_SHA });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("atokr subject-presence: null subject is rejected with subject_must_be_present (SP2)", () => {
  const r = checkAtokrSubjectPresence({ subject: null });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_present");
});

test("atokr subject-presence: empty string is rejected with subject_must_be_present (SP3)", () => {
  const r = checkAtokrSubjectPresence({ subject: "" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_present");
});

test("atokr subject-presence: non-sha256 string is rejected with subject_must_be_sha256 (SP4)", () => {
  const r = checkAtokrSubjectPresence({ subject: "did:web:subject.example" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("atokr subject-presence: uppercase hex is rejected with subject_must_be_sha256 (SP5)", () => {
  const r = checkAtokrSubjectPresence({ subject: "sha256:" + "A".repeat(64) });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("atokr subject-presence: wrong length hex (63 chars) is rejected with subject_must_be_sha256 (SP6)", () => {
  const r = checkAtokrSubjectPresence({ subject: "sha256:" + "a".repeat(63) });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});
