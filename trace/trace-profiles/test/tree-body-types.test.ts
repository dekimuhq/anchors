import { test } from "node:test";
import assert from "node:assert/strict";
import type { AgTRTreeBody } from "../src/body.ts";

test("AgTRTreeBody accepts a well-formed two-span tree", () => {
  const b: AgTRTreeBody = {
    profile: "agent.trace",
    trace_id: "a".repeat(32),
    request_id_commit: "sha256:" + "a".repeat(64),
    capability: "operator.draft-reminder",
    spans: [
      { span_id: "1".repeat(16), parent_span_id: null, name: "stage.execute", start_offset_ms: 0, duration_ms: 41, status: "ok" },
      { span_id: "2".repeat(16), parent_span_id: "1".repeat(16), name: "llm.call", start_offset_ms: 3, duration_ms: 30, status: "ok" },
    ],
    spans_root: "sha256:" + "b".repeat(64),
    outcome: "ok",
    started_at: "2026-07-01T10:00:00Z",
    total_ms: 43,
  };
  assert.equal(b.spans.length, 2);
  assert.equal(b.spans[1].parent_span_id, b.spans[0].span_id);
});
