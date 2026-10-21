import { test } from "node:test";
import assert from "node:assert/strict";
import { contractHash } from "../src/contract-hash.ts";
import type { AnchorContract } from "../src/types.ts";

const base: AnchorContract = {
  id: "escrow.fund",
  version: "1.0.0",
  preconditions: [{ claimType: "ar.transfer.v1" }],
  transition: { from: "awaiting_funds", to: "funded" },
};

test("contractHash is a sha256: prefixed hex digest", () => {
  const h = contractHash(base);
  assert.match(h, /^sha256:[0-9a-f]{64}$/);
});

test("contractHash is stable regardless of key insertion order", () => {
  const reordered: AnchorContract = {
    version: "1.0.0",
    transition: { to: "funded", from: "awaiting_funds" },
    id: "escrow.fund",
    preconditions: [{ claimType: "ar.transfer.v1" }],
  };
  assert.equal(contractHash(base), contractHash(reordered));
});

test("contractHash changes when the rule changes", () => {
  const changed: AnchorContract = { ...base, transition: { from: "awaiting_funds", to: "released" } };
  assert.notEqual(contractHash(base), contractHash(changed));
});
