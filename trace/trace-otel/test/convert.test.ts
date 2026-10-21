import { test } from "node:test";
import assert from "node:assert/strict";
import { toAgTRTree } from "../src/convert.ts";
import { otelSpan } from "./_helpers/otel-fixtures.ts";

test("toAgTRTree maps OTel spans → skeleton + detail, offsets relative to started_at", () => {
  const root = otelSpan();
  const child = otelSpan({
    name: "llm.call",
    spanContext: () => ({ traceId: "a".repeat(32), spanId: "2".repeat(16) }),
    parentSpanId: "1".repeat(16),
    startTime: [1_780_000_000, 3_000_000],
    endTime: [1_780_000_000, 33_000_000],
  });
  const { skeleton, detail, trace_id, started_at, total_ms } = toAgTRTree([root, child] as never[]);
  assert.equal(trace_id, "a".repeat(32));
  assert.equal(skeleton.length, 2);
  assert.equal(skeleton[0].parent_span_id, null);
  assert.equal(skeleton[1].parent_span_id, "1".repeat(16));
  assert.equal(skeleton[0].start_offset_ms, 0);
  assert.equal(skeleton[1].start_offset_ms, 3);
  assert.equal(skeleton[0].duration_ms, 41);
  assert.equal(skeleton[1].status, "ok");
  assert.ok(detail["2".repeat(16)]);
  assert.match(started_at, /^\d{4}-\d{2}-\d{2}T/);
  assert.ok(total_ms >= 41);
});

test("OTel StatusCode ERROR → 'error', UNSET → 'unset'", () => {
  const err = otelSpan({ status: { code: 2 } });
  const uns = otelSpan({ status: { code: 0 }, spanContext: () => ({ traceId: "a".repeat(32), spanId: "3".repeat(16) }) });
  assert.equal(toAgTRTree([err] as never[]).skeleton[0].status, "error");
  assert.equal(toAgTRTree([uns] as never[]).skeleton[0].status, "unset");
});
