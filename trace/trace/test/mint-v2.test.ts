import { test } from "node:test";
import assert from "node:assert/strict";
import { mintTraceV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { goodTreeInput } from "./_helpers/tree-fixtures.ts";
import { makeResolveKey } from "./_helpers/fixtures.ts";

test("mint v2 → verify round-trip, subject null, claim_type ar.trace.v2", async () => {
  const env = await mintTraceV2(goodTreeInput());
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.trace.v2");
  assert.equal(env.subject, null);
  assert.match((env.body as { spans_root: string }).spans_root, /^sha256:[0-9a-f]{64}$/);
  const res = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(res.signature_valid, true, (res as { reason?: string }).reason ?? "ok");
});
test("mint rejects an invalid tree (cycle)", async () => {
  const bad = goodTreeInput();
  const [a, b] = [bad.spans[0].span_id, bad.spans[1].span_id];
  bad.spans = [{ ...bad.spans[0], parent_span_id: b }, { ...bad.spans[1], parent_span_id: a }];
  await assert.rejects(() => mintTraceV2(bad), /invalid body/);
});
test("tampering a span's duration breaks the signature", async () => {
  const env = await mintTraceV2(goodTreeInput());
  (env.body as { spans: { duration_ms: number }[] }).spans[0].duration_ms = 9999;
  const res = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(res.signature_valid, false);
});
