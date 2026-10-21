import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateContract } from "../src/evaluate.ts";
import type { AnchorContract } from "../src/types.ts";
import { makeEnvelope, verified } from "./_fixtures.ts";

const fundContract: AnchorContract = {
  id: "escrow.fund",
  version: "1.0.0",
  preconditions: [{ as: "payment", claimType: "ar.transfer.v1", subjectEquals: "deal-42" }],
  transition: { from: "awaiting_funds", to: "funded" },
  where: { ">=": [{ var: "anchors.payment.body.amount" }, 100] },
};

test("fires when preconditions + combined predicate hold", () => {
  const pay = verified(makeEnvelope({ claim_type: "ar.transfer.v1", subject: "deal-42", body: { amount: 150 } }));
  const v = evaluateContract(fundContract, [pay]);
  assert.equal(v.fired, true);
  assert.equal(v.to, "funded");
  assert.ok(v.matched?.payment);
  assert.match(v.contractHash, /^sha256:/);
});

test("does not fire when the combined predicate is false", () => {
  const pay = verified(makeEnvelope({ claim_type: "ar.transfer.v1", subject: "deal-42", body: { amount: 50 } }));
  const v = evaluateContract(fundContract, [pay]);
  assert.equal(v.fired, false);
  assert.equal(v.reason, "predicate_evaluation_false");
});

test("does not fire when a precondition is unmatched", () => {
  const v = evaluateContract(fundContract, [verified(makeEnvelope({ claim_type: "ar.consent.v1" }))]);
  assert.equal(v.fired, false);
  assert.equal(v.reason, "precondition_unmatched");
});

test("refuses on an unsigned anchor", () => {
  const pay = verified(makeEnvelope({ claim_type: "ar.transfer.v1", subject: "deal-42", body: { amount: 150 } }), { signature_valid: false });
  const v = evaluateContract(fundContract, [pay]);
  assert.equal(v.fired, false);
  assert.equal(v.reason, "anchor_signature_invalid");
});

test("a contract with no `where` fires on preconditions alone", () => {
  const { where: _omit, ...rest } = fundContract;
  const c: AnchorContract = rest;
  const pay = verified(makeEnvelope({ claim_type: "ar.transfer.v1", subject: "deal-42", body: { amount: 1 } }));
  assert.equal(evaluateContract(c, [pay]).fired, true);
});
