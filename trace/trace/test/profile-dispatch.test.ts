/**
 * A1 regression: the registered `agent.trace` advisory profile validator must
 * shape-dispatch — v2 span-tree bodies (`spans`) → the tree validator, v1 flat
 * bodies (`stages`) → the flat validator. Before the fix the family registered
 * ONLY the v1 flat adapter, so a v2 body explicitly profile-validated would run
 * the v1 `stages` validator and emit a spurious `trace.stages_empty`.
 *
 * We invoke the registered validator the way the verify pipeline does:
 * `(envelope, body, ctx) => ProfileStateEntry` — envelope/ctx unused by the
 * (pure body-shaped) trace validators.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import { traceFamily } from "../src/family.ts";

/** The single registered advisory validator (only `agent.trace` is wired). */
const profileValidator = traceFamily.profileValidators[0];
const envStub = {} as unknown as Envelope;
const ctxStub = {};

const validV2Body = {
  profile: "agent.trace",
  trace_id: "a".repeat(32),
  request_id_commit: "sha256:" + "a".repeat(64),
  spans: [
    { span_id: "1".repeat(16), parent_span_id: null, name: "stage.execute", start_offset_ms: 0, duration_ms: 10, status: "ok" },
  ],
  spans_root: "sha256:" + "b".repeat(64),
  outcome: "ok",
  started_at: "2026-07-01T10:00:00Z",
  total_ms: 10,
};

const validV1Body = {
  profile: "agent.trace",
  request_id_commit: "sha256:" + "a".repeat(64),
  stages: [{ stage: "execute", ms: 10, status: "ok" }],
  outcome: "ok",
  trace_commit: "sha256:" + "b".repeat(64),
  started_at: "2026-06-20T10:00:00Z",
  total_ms: 10,
};

test("PD1: v2 (span-tree) body → tree validator, no stages error, ok", () => {
  const r = profileValidator(envStub, validV2Body, ctxStub);
  // Would be reason "trace.stages_empty" if the v1 `stages` validator ran.
  assert.notEqual(r.reason, "trace.stages_empty");
  assert.equal(r.profile_id, "agent.trace");
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("PD2: v1 (flat) body → flat validator, still ok (v1 path intact)", () => {
  const r = profileValidator(envStub, validV1Body, ctxStub);
  assert.equal(r.profile_id, "agent.trace");
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});
