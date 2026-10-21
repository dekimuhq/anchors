/**
 * Tests for `checkAsrSubjectPresence` — D10-ASR-5 enforcement.
 *
 * The callback is exercised through the manifest in family.test.ts; this
 * suite hits the callback directly so reason codes and edge-cases are
 * pinned independently of the factory pipeline.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { checkAsrSubjectPresence } from "../src/subject-presence.ts";

const ANY_BODY = { event_type: "request.received" };
const sha = (c: string): string => `sha256:${c.repeat(64)}`;

test("accepts canonical sha256:<64-hex> subject", () => {
  for (const c of ["0", "9", "a", "f", "ab"]) {
    const repeat = c.length === 1 ? c.repeat(64) : c.repeat(32);
    const subject = `sha256:${repeat}`;
    assert.deepEqual(
      checkAsrSubjectPresence({ subject, body: ANY_BODY }),
      { ok: true },
      `subject ${subject} MUST be accepted`,
    );
  }
});

test("rejects null subject as subject_missing", () => {
  assert.deepEqual(
    checkAsrSubjectPresence({ subject: null, body: ANY_BODY }),
    { ok: false, reason: "subject_missing" },
  );
});

test("rejects undefined subject as subject_missing", () => {
  assert.deepEqual(
    checkAsrSubjectPresence({ subject: undefined, body: ANY_BODY }),
    { ok: false, reason: "subject_missing" },
  );
});

test("rejects empty string as subject_missing", () => {
  assert.deepEqual(
    checkAsrSubjectPresence({ subject: "", body: ANY_BODY }),
    { ok: false, reason: "subject_missing" },
  );
});

test("rejects non-sha256 prefix as subject_invalid_form", () => {
  for (const subject of [
    "md5:" + "a".repeat(32),
    "sha1:" + "a".repeat(40),
    "sha512:" + "a".repeat(128),
    "did:web:example.com",
    "sha256",
    "sha256:",
  ]) {
    assert.deepEqual(
      checkAsrSubjectPresence({ subject, body: ANY_BODY }),
      { ok: false, reason: "subject_invalid_form" },
      `subject ${subject} MUST reject as subject_invalid_form`,
    );
  }
});

test("rejects short hex (<64 chars) as subject_invalid_form", () => {
  assert.deepEqual(
    checkAsrSubjectPresence({ subject: "sha256:" + "a".repeat(63), body: ANY_BODY }),
    { ok: false, reason: "subject_invalid_form" },
  );
});

test("rejects long hex (>64 chars) as subject_invalid_form", () => {
  assert.deepEqual(
    checkAsrSubjectPresence({ subject: "sha256:" + "a".repeat(65), body: ANY_BODY }),
    { ok: false, reason: "subject_invalid_form" },
  );
});

test("rejects uppercase hex as subject_invalid_form (canonical form is lowercase)", () => {
  assert.deepEqual(
    checkAsrSubjectPresence({ subject: sha("A"), body: ANY_BODY }),
    { ok: false, reason: "subject_invalid_form" },
  );
});

test("rejects non-hex character within the 64-char block", () => {
  assert.deepEqual(
    checkAsrSubjectPresence({ subject: "sha256:" + "g".repeat(64), body: ANY_BODY }),
    { ok: false, reason: "subject_invalid_form" },
  );
  assert.deepEqual(
    checkAsrSubjectPresence({ subject: "sha256:" + "z".repeat(64), body: ANY_BODY }),
    { ok: false, reason: "subject_invalid_form" },
  );
});

test("rejects non-string subject as subject_invalid_form (defensive)", () => {
  // SubjectPresenceCheckInput types subject as string | null | undefined,
  // but the factory may pass through bad data — the callback must not throw.
  for (const subject of [42, true, [], {}]) {
    const r = checkAsrSubjectPresence({ subject: subject as unknown as string, body: ANY_BODY });
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.reason, "subject_invalid_form");
    }
  }
});
