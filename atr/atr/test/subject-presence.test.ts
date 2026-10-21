/**
 * Subject-presence tests for ATR — per-event-type split.
 *
 * FAMILY-CONSISTENCY.md §3: ATR has a per-event split:
 *   - `transfer`              → subject MUST be sha256:<hex>
 *   - `arrangement`           → subject MUST be null
 *   - `tia`                   → subject MUST be null
 *   - `suspension`            → subject MUST be null
 *   - unknown event_type      → subject MUST be null (fall-through)
 *
 * Coverage per event_type:
 *   SP1 — valid sha256:<hex> subject on transfer               → ok
 *   SP2 — null subject on transfer                             → subject_must_be_present
 *   SP3 — empty string subject on transfer                     → subject_must_be_present
 *   SP4 — non-sha256 string on transfer                        → subject_must_be_sha256
 *   SP5 — uppercase hex on transfer                            → subject_must_be_sha256
 *   SP6 — wrong-length hex on transfer (63 chars)              → subject_must_be_sha256
 *   SP7 — null subject on arrangement                          → ok
 *   SP8 — non-null subject on arrangement                      → subject_must_be_null
 *   SP9 — null subject on tia                                  → ok
 *   SP10 — non-null subject on tia                             → subject_must_be_null
 *   SP11 — null subject on suspension                          → ok
 *   SP12 — non-null subject on suspension                      → subject_must_be_null
 *   SP13 — null subject on unknown event_type                  → ok (fall-through)
 *   SP14 — non-null subject on unknown event_type              → subject_must_be_null
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { checkAtrSubjectPresence } from "../src/subject-presence.ts";

const VALID_SHA = "sha256:" + "a".repeat(64);

// ── transfer — must-be-sha256 ─────────────────────────────────────────────────

test("transfer: valid sha256:<hex> subject is accepted (SP1)", () => {
  const r = checkAtrSubjectPresence({ subject: VALID_SHA, event_type: "transfer" });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("transfer: null subject is rejected with subject_must_be_present (SP2)", () => {
  const r = checkAtrSubjectPresence({ subject: null, event_type: "transfer" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_present");
});

test("transfer: empty string subject is rejected with subject_must_be_present (SP3)", () => {
  const r = checkAtrSubjectPresence({ subject: "", event_type: "transfer" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_present");
});

test("transfer: non-sha256 string is rejected with subject_must_be_sha256 (SP4)", () => {
  const r = checkAtrSubjectPresence({ subject: "did:web:example.com", event_type: "transfer" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("transfer: uppercase hex is rejected with subject_must_be_sha256 (SP5)", () => {
  const r = checkAtrSubjectPresence({ subject: "sha256:" + "A".repeat(64), event_type: "transfer" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("transfer: wrong-length hex (63 chars) is rejected with subject_must_be_sha256 (SP6)", () => {
  const r = checkAtrSubjectPresence({ subject: "sha256:" + "a".repeat(63), event_type: "transfer" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

// ── arrangement — must-be-null ────────────────────────────────────────────────

test("arrangement: null subject is accepted (SP7)", () => {
  const r = checkAtrSubjectPresence({ subject: null, event_type: "arrangement" });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("arrangement: non-null subject is rejected with subject_must_be_null (SP8)", () => {
  const r = checkAtrSubjectPresence({ subject: VALID_SHA, event_type: "arrangement" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

// ── tia — must-be-null ────────────────────────────────────────────────────────

test("tia: null subject is accepted (SP9)", () => {
  const r = checkAtrSubjectPresence({ subject: null, event_type: "tia" });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("tia: non-null subject is rejected with subject_must_be_null (SP10)", () => {
  const r = checkAtrSubjectPresence({ subject: VALID_SHA, event_type: "tia" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

// ── suspension — must-be-null ─────────────────────────────────────────────────

test("suspension: null subject is accepted (SP11)", () => {
  const r = checkAtrSubjectPresence({ subject: null, event_type: "suspension" });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("suspension: non-null subject is rejected with subject_must_be_null (SP12)", () => {
  const r = checkAtrSubjectPresence({ subject: VALID_SHA, event_type: "suspension" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

// ── unknown event_type — falls through to must-be-null ───────────────────────

test("unknown event_type: null subject falls through to must-be-null branch and is accepted (SP13)", () => {
  const r = checkAtrSubjectPresence({ subject: null, event_type: "unknown_event" });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("unknown event_type: non-null subject is rejected with subject_must_be_null (SP14)", () => {
  const r = checkAtrSubjectPresence({ subject: VALID_SHA, event_type: "unknown_event" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});
