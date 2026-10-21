import { test } from "node:test";
import assert from "node:assert/strict";
import { validateAgentTraceTree } from "../src/agent-trace-tree.ts";
import type { AgTRTreeBody } from "../src/body.ts";

const good: AgTRTreeBody = {
  profile: "agent.trace",
  trace_id: "a".repeat(32),
  request_id_commit: "sha256:" + "a".repeat(64),
  spans: [{ span_id: "1".repeat(16), parent_span_id: null, name: "stage.execute", start_offset_ms: 0, duration_ms: 10, status: "ok" }],
  spans_root: "sha256:" + "b".repeat(64),
  outcome: "ok",
  started_at: "2026-07-01T10:00:00Z",
  total_ms: 10,
};

test("valid tree → no errors", () => {
  assert.deepEqual(validateAgentTraceTree(good).errors, []);
});
test("error outcome without error_span_id → flagged", () => {
  assert.ok(validateAgentTraceTree({ ...good, outcome: "error" }).errors.includes("trace.error_span_missing"));
});
test("empty spans → flagged", () => {
  assert.ok(validateAgentTraceTree({ ...good, spans: [] }).errors.includes("trace.spans_empty"));
});
test("caveats_consumed without credential_id → orphan", () => {
  assert.ok(validateAgentTraceTree({ ...good, caveats_consumed: { data_scope: "x", spend_step: 0, capability: "y" } }).errors.includes("trace.caveats_orphan"));
});
