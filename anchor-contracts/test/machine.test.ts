import { test } from "node:test";
import assert from "node:assert/strict";
import { createMachine, fireTransition } from "../src/machine.ts";
import type { MachineDefinition } from "../src/types.ts";
import { makeEnvelope, verified } from "./_fixtures.ts";

const def: MachineDefinition = {
  states: ["awaiting_funds", "funded", "released"],
  initial: "awaiting_funds",
  contracts: [
    {
      id: "fund", version: "1.0.0",
      preconditions: [{ as: "payment", claimType: "ar.transfer.v1", subjectEquals: "deal-42" }],
      transition: { from: "awaiting_funds", to: "funded" },
      where: { ">=": [{ var: "anchors.payment.body.amount" }, 100] },
    },
    {
      id: "release", version: "1.0.0",
      preconditions: [{ as: "approval", claimType: "ar.attestation.v1", subjectEquals: "deal-42" }],
      transition: { from: "funded", to: "released" },
    },
  ],
};

const payment = () => verified(makeEnvelope({ claim_type: "ar.transfer.v1", subject: "deal-42", body: { amount: 150 } }));
const approval = () => verified(makeEnvelope({ claim_type: "ar.attestation.v1", subject: "deal-42" }));

test("createMachine starts at initial with an empty trail", () => {
  const s = createMachine(def);
  assert.equal(s.current, "awaiting_funds");
  assert.deepEqual(s.trail, []);
});

test("a valid transition advances state and records the trail", () => {
  const s0 = createMachine(def);
  const { state: s1, verdict } = fireTransition(def, s0, "fund", [payment()]);
  assert.equal(verdict.fired, true);
  assert.equal(s1.current, "funded");
  assert.equal(s1.trail.length, 1);
  assert.equal(s1.trail[0]!.contractId, "fund");
});

test("firing from the wrong state refuses and does not mutate", () => {
  const s0 = createMachine(def);
  const { state: s1, verdict } = fireTransition(def, s0, "release", [approval()]);
  assert.equal(verdict.fired, false);
  assert.equal(verdict.reason, "wrong_from_state");
  assert.equal(s1.current, "awaiting_funds");
  assert.equal(s1.trail.length, 0);
});

test("unknown contract id refuses", () => {
  const s0 = createMachine(def);
  const { verdict } = fireTransition(def, s0, "nope", []);
  assert.equal(verdict.fired, false);
  assert.equal(verdict.reason, "unknown_contract");
});

test("input state is never mutated (immutability)", () => {
  const s0 = createMachine(def);
  fireTransition(def, s0, "fund", [payment()]);
  assert.equal(s0.current, "awaiting_funds");
  assert.equal(s0.trail.length, 0);
});

test("a failed predicate does not advance state", () => {
  const s0 = createMachine(def);
  const weak = verified(makeEnvelope({ claim_type: "ar.transfer.v1", subject: "deal-42", body: { amount: 5 } }));
  const { state: s1, verdict } = fireTransition(def, s0, "fund", [weak]);
  assert.equal(verdict.fired, false);
  assert.equal(s1.current, "awaiting_funds");
});
