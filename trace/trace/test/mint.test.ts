import { test } from "node:test";
import assert from "node:assert/strict";
import { mintTraceV1 } from "../src/issue/mint-v1.ts";
import { verifyReceipt } from "../src/index.ts";
import { goodTraceInput, makeResolveKey } from "./_helpers/fixtures.ts";

test("mint → verify round-trip valid", async () => {
  const env = await mintTraceV1(goodTraceInput());
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.trace.v1");
  assert.equal(env.subject, null);
  const res = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(res.signature_valid, true);
});
test("mint rejects invalid body (error outcome, no error_stage)", async () => {
  await assert.rejects(() => mintTraceV1({ ...goodTraceInput(), outcome: "error" }), /invalid body/);
});
test("tamper with a stage ms breaks signature", async () => {
  const env = await mintTraceV1(goodTraceInput());
  (env.body as { stages: { ms: number }[] }).stages[0].ms = 9999;
  const res = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(res.signature_valid, false);
});
