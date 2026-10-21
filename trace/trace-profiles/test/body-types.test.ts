import { test } from "node:test";
import assert from "node:assert/strict";
import type { AgTRBody } from "../src/body.ts";

test("AgTRBody accepts a well-formed agent.trace value", () => {
  const b: AgTRBody = {
    profile: "agent.trace",
    request_id_commit: "sha256:" + "a".repeat(64),
    capability: "operator.draft-reminder",
    stages: [
      { stage: "validate", ms: 2, status: "ok" },
      { stage: "execute", ms: 41, status: "ok" },
    ],
    outcome: "ok",
    trace_commit: "sha256:" + "b".repeat(64),
    started_at: "2026-06-20T10:00:00Z",
    total_ms: 43,
  };
  assert.equal(b.stages.length, 2);
  assert.equal(b.outcome, "ok");
});
