import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyTraceTreeBody } from "../src/verify-tree.ts";

const S = (id: string, parent: string | null, name = "s", ms = 1) =>
  ({ span_id: id.repeat(16).slice(0, 16), parent_span_id: parent, name, start_offset_ms: 0, duration_ms: ms, status: "ok" as const });
const good = () => ({
  profile: "agent.trace",
  trace_id: "a".repeat(32),
  request_id_commit: "sha256:" + "a".repeat(64),
  spans: [S("1", null), S("2", "1".repeat(16).slice(0, 16))],
  spans_root: "sha256:" + "b".repeat(64),
  outcome: "ok",
  started_at: "2026-07-01T10:00:00Z",
  total_ms: 5,
});

test("valid tree → valid:true", () => {
  const r = verifyTraceTreeBody(good());
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.ok(r.body);
});
test("non-object → body.not_object", () => {
  assert.deepEqual(verifyTraceTreeBody(null).errors, ["body.not_object"]);
});
test("bad trace_id → trace_id.invalid", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), trace_id: "xyz" }).errors.includes("trace_id.invalid"));
});
test("empty spans → spans.empty", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), spans: [] }).errors.includes("spans.empty"));
});
test("duplicate span_id → spans.span_id.duplicate", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), spans: [S("1", null), S("1", null)] }).errors.includes("spans.span_id.duplicate"));
});
test("unresolved parent → spans[1].parent.unresolved", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), spans: [S("1", null), S("2", "9".repeat(16))] }).errors.includes("spans[1].parent.unresolved"));
});
test("no root → spans.no_root", () => {
  const a = "1".repeat(16), b = "2".repeat(16);
  assert.ok(verifyTraceTreeBody({ ...good(), spans: [{ ...S("1", null), span_id: a, parent_span_id: b }, { ...S("2", null), span_id: b, parent_span_id: a }] }).errors.includes("spans.no_root"));
});
test("cycle → spans.cycle", () => {
  const a = "1".repeat(16), b = "2".repeat(16), c = "3".repeat(16);
  const spans = [
    { ...S("r", null), span_id: c, parent_span_id: null },
    { ...S("1", null), span_id: a, parent_span_id: b },
    { ...S("2", null), span_id: b, parent_span_id: a },
  ];
  assert.ok(verifyTraceTreeBody({ ...good(), spans }).errors.includes("spans.cycle"));
});
test("outcome=error requires error_span_id", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), outcome: "error" }).errors.includes("error_span_id.missing"));
});
test("outcome=error with resolvable error_span_id → valid", () => {
  assert.equal(verifyTraceTreeBody({ ...good(), outcome: "error", error_span_id: "1".repeat(16) }).valid, true);
});
test("bad started_at → started_at.invalid", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), started_at: "2026-13-99" }).errors.includes("started_at.invalid"));
});
test("caveats_consumed without credential_id → orphan", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), caveats_consumed: { data_scope: "x", spend_step: 0, capability: "y" } }).errors.includes("caveats_consumed.orphan"));
});

test("valid multi-root forest → valid:true (OTel allows multiple roots)", () => {
  const a = "1".repeat(16), b = "2".repeat(16);
  const spans = [{ ...S("1", null), span_id: a, parent_span_id: null }, { ...S("2", null), span_id: b, parent_span_id: null }];
  assert.equal(verifyTraceTreeBody({ ...good(), spans }).valid, true);
});
test("valid deep 4-level chain → valid:true (no false-positive cycle)", () => {
  const ids = ["1", "2", "3", "4"].map((c) => c.repeat(16));
  const spans = ids.map((id, i) => ({ ...S("x", null), span_id: id, parent_span_id: i === 0 ? null : ids[i - 1] }));
  assert.equal(verifyTraceTreeBody({ ...good(), spans }).valid, true);
});
test("error_span_id present but not a real span → error_span_id.unresolved", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), error_span_id: "9".repeat(16) }).errors.includes("error_span_id.unresolved"));
});
test("malformed policy_hash → policy_hash.invalid", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), policy_hash: "nope" }).errors.includes("policy_hash.invalid"));
});
test("empty credential_id → credential_id.invalid", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), credential_id: "" }).errors.includes("credential_id.invalid"));
});
test("caveats_consumed with credential_id but malformed shape → caveats_consumed.invalid", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), credential_id: "cred-1", caveats_consumed: { data_scope: "x" } }).errors.includes("caveats_consumed.invalid"));
});
test("span with negative start_offset_ms → spans[0].start_offset_ms.invalid", () => {
  const spans = [{ ...S("1", null), start_offset_ms: -1 }];
  assert.ok(verifyTraceTreeBody({ ...good(), spans }).errors.includes("spans[0].start_offset_ms.invalid"));
});
test("span with invalid status → spans[0].status.invalid", () => {
  const spans = [{ ...S("1", null), status: "bogus" }];
  assert.ok(verifyTraceTreeBody({ ...good(), spans }).errors.includes("spans[0].status.invalid"));
});
test("bad trace_id length (31 hex) → trace_id.invalid", () => {
  assert.ok(verifyTraceTreeBody({ ...good(), trace_id: "a".repeat(31) }).errors.includes("trace_id.invalid"));
});
