/**
 * Tests for the AgTR family manifest (defineFamily wiring). Chip 19, ar.trace.v1.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { traceFamily } from "../src/family.ts";

test("F1: acronym is AgTR", () => {
  assert.equal(traceFamily.meta.acronym, "AgTR");
});

test("F2: name is Anchored Agent-Trace Receipts", () => {
  assert.equal(traceFamily.meta.name, "Anchored Agent-Trace Receipts");
});

test("F3: owns ar.trace.v1 + ar.trace.v2 claim_types", () => {
  assert.deepEqual([...traceFamily.meta.claim_types], ["ar.trace.v1", "ar.trace.v2"]);
});

test("F4: chip is 19", () => {
  assert.equal(traceFamily.meta.chip, 19);
});

test("F5: status_list_slot is null (non-revocable)", () => {
  assert.equal(traceFamily.meta.status_list_slot, null);
});

test("F6: subject_presence is must-be-null", () => {
  assert.equal(traceFamily.meta.subject_presence, "must-be-null");
});

test("F7: tsa_upgrade_path is free", () => {
  assert.equal(traceFamily.meta.tsa_upgrade_path, "free");
});

test("F8: continuity is false (single-receipt, no chain)", () => {
  assert.equal(traceFamily.meta.continuity, false);
});

test("F9: spec_path points at the AgTR design doc", () => {
  assert.match(traceFamily.meta.spec_path, /^https:\/\/github\.com\/dekimuhq\/anchors-spec\/tree\/main\/trace$/);
});

test("F10: agent.trace profile is registered", () => {
  assert.equal(traceFamily.hasProfile("agent.trace"), true);
});

test("F11: exactly one profile registered (agent.trace)", () => {
  assert.deepEqual([...traceFamily.profileIds], ["agent.trace"]);
});

test("F12: validateBody accepts a valid agent.trace body", () => {
  const r = traceFamily.validateBody({
    profile: "agent.trace",
    request_id_commit: "sha256:" + "a".repeat(64),
    stages: [{ stage: "execute", ms: 10, status: "ok" }],
    outcome: "ok",
    trace_commit: "sha256:" + "b".repeat(64),
    started_at: "2026-06-20T10:00:00Z",
    total_ms: 10,
  });
  assert.equal(r.ok, true);
});

test("F13: validateBody rejects a non-object with body.not_object reason", () => {
  const r = traceFamily.validateBody("nope");
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "body.not_object");
});

test("F14: checkSubjectPresence(null) → ok (must-be-null rule)", () => {
  const r = traceFamily.checkSubjectPresence(null);
  assert.equal(r.ok, true);
});

test("F15: checkSubjectPresence('some-subject') → not ok (must-be-null rule)", () => {
  const r = traceFamily.checkSubjectPresence("sha256:" + "a".repeat(64));
  assert.equal(r.ok, false);
});
