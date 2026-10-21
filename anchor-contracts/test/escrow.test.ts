import { test } from "node:test";
import assert from "node:assert/strict";
import { createMachine, fireTransition } from "../src/index.ts";
import type { MachineDefinition } from "../src/index.ts";
import { makeEnvelope, verified } from "./_fixtures.ts";

const escrow: MachineDefinition = {
  states: ["awaiting_funds", "funded", "released"],
  initial: "awaiting_funds",
  contracts: [
    {
      id: "fund", version: "1.0.0",
      preconditions: [{ as: "payment", claimType: "ar.transfer.v1", issuers: ["did:web:buyer.example"], subjectEquals: "deal-42" }],
      transition: { from: "awaiting_funds", to: "funded" },
      where: { ">=": [{ var: "anchors.payment.body.amount" }, 100] },
    },
    {
      id: "release", version: "1.0.0",
      preconditions: [{ as: "approval", claimType: "ar.attestation.v1", issuers: ["did:web:escrow.example"], subjectEquals: "deal-42" }],
      transition: { from: "funded", to: "released" },
    },
  ],
};

test("end-to-end escrow: fund then release, trail has both", () => {
  let s = createMachine(escrow);

  const payment = verified(makeEnvelope({ claim_type: "ar.transfer.v1", iss: "did:web:buyer.example", subject: "deal-42", body: { amount: 250 } }));
  ({ state: s } = fireTransition(escrow, s, "fund", [payment]));
  assert.equal(s.current, "funded");

  const approval = verified(makeEnvelope({ claim_type: "ar.attestation.v1", iss: "did:web:escrow.example", subject: "deal-42" }));
  ({ state: s } = fireTransition(escrow, s, "release", [approval]));
  assert.equal(s.current, "released");

  assert.deepEqual(s.trail.map((v) => v.contractId), ["fund", "release"]);
  assert.ok(s.trail.every((v) => v.fired && v.contractHash.startsWith("sha256:")));
});

test("two parties evaluating the same inputs reach the same verdict (determinism)", () => {
  const payment = verified(makeEnvelope({ claim_type: "ar.transfer.v1", iss: "did:web:buyer.example", subject: "deal-42", body: { amount: 250 } }));
  const a = fireTransition(escrow, createMachine(escrow), "fund", [payment]).verdict;
  const b = fireTransition(escrow, createMachine(escrow), "fund", [payment]).verdict;
  assert.deepEqual(a, b);
});
