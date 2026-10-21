import { test } from "node:test";
import assert from "node:assert/strict";
import { validateAgentTrace } from "../src/agent-trace.ts";
import type { AgTRBody } from "../src/body.ts";

const good: AgTRBody = {
  profile: "agent.trace",
  request_id_commit: "sha256:" + "a".repeat(64),
  stages: [{ stage: "execute", ms: 10, status: "ok" }],
  outcome: "ok",
  trace_commit: "sha256:" + "b".repeat(64),
  started_at: "2026-06-20T10:00:00Z",
  total_ms: 10,
};

test("valid agent.trace → no errors", () => {
  assert.deepEqual(validateAgentTrace(good).errors, []);
});
test("error outcome without error_stage → flagged", () => {
  assert.ok(validateAgentTrace({ ...good, outcome: "error" }).errors.includes("trace.error_stage_missing"));
});
test("empty stages → flagged", () => {
  assert.ok(validateAgentTrace({ ...good, stages: [] }).errors.includes("trace.stages_empty"));
});
test("caveats_consumed without credential_id → orphan", () => {
  assert.ok(validateAgentTrace({ ...good, caveats_consumed: { data_scope: "x", spend_step: 0, capability: "y" } }).errors.includes("trace.caveats_orphan"));
});
