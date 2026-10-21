import { test } from "node:test";
import assert from "node:assert/strict";
import type { InclBlock, CheckpointNote, LogStatus } from "../src/types.ts";

test("InclBlock with a promise type-checks and round-trips JSON", () => {
  const b: InclBlock = { log_id: "dekimu-anchors-log-2026", leaf: "sha256:00", promise: { timestamp: "2026-01-01T00:00:00Z", sig: "AAAA" } };
  assert.equal(JSON.parse(JSON.stringify(b)).log_id, "dekimu-anchors-log-2026");
});

test("LogStatus is the closed tri-state plus invalid", () => {
  const ok: LogStatus[] = ["logged_proven", "logged_promised", "not_logged", "incl_invalid"];
  assert.equal(ok.length, 4);
});
