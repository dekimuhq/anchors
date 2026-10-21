import { test } from "node:test";
import assert from "node:assert/strict";
import { buildSpansRoot } from "../src/spans-root.ts";

test("buildSpansRoot is deterministic for the same salts + detail", () => {
  const spans = [{ span_id: "1".repeat(16) }, { span_id: "2".repeat(16) }] as { span_id: string }[];
  const detail = { ["1".repeat(16)]: { in: "x" }, ["2".repeat(16)]: { out: "y" } };
  const salts = { saltFor: (id: string) => "salt-" + id };
  const a = buildSpansRoot(spans, detail, salts);
  const b = buildSpansRoot(spans, detail, salts);
  assert.match(a.spans_root, /^sha256:[0-9a-f]{64}$/);
  assert.equal(a.spans_root, b.spans_root);
  assert.equal(a.leaves.length, 2);
});
test("changing one span's detail changes the root", () => {
  const spans = [{ span_id: "1".repeat(16) }] as { span_id: string }[];
  const salts = { saltFor: (id: string) => "salt-" + id };
  const a = buildSpansRoot(spans, { ["1".repeat(16)]: { in: "x" } }, salts);
  const b = buildSpansRoot(spans, { ["1".repeat(16)]: { in: "z" } }, salts);
  assert.notEqual(a.spans_root, b.spans_root);
});
