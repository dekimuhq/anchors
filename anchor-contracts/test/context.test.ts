import { test } from "node:test";
import assert from "node:assert/strict";
import { buildContext } from "../src/context.ts";
import { makeEnvelope } from "./_fixtures.ts";

test("wraps matched envelopes under `anchors.<key>`", () => {
  const pay = makeEnvelope({ claim_type: "ar.transfer.v1", body: { amount: 100 } });
  const ctx = buildContext({ payment: pay });
  assert.equal((ctx.anchors.payment!.body as { amount: number }).amount, 100);
});

test("the context is var-addressable by the predicate evaluator", async () => {
  const { evaluatePredicate } = await import("@dekimuhq/anchors-envelope");
  const pay = makeEnvelope({ claim_type: "ar.transfer.v1", subject: "deal-42", body: { amount: 100 } });
  const ok = makeEnvelope({ claim_type: "ar.attestation.v1", subject: "deal-42" });
  const ctx = buildContext({ payment: pay, approval: ok });
  const ast = { "==": [{ var: "anchors.payment.subject" }, { var: "anchors.approval.subject" }] };
  assert.equal(evaluatePredicate(ast as never, ctx), true);
});
