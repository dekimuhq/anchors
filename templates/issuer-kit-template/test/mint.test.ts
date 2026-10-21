// @dekimuhq/<member>-issuer-kit — mint test scaffold
//
// TDD: write failing tests for §7 issuer-kit semantics BEFORE implementing src/mint.ts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair, mint<MEMBER> } from "../src/index.ts";

test("mint<MEMBER>: produces well-formed v=2 envelope", async () => {
  const kp = await generateKeypair();
  const { receipt } = await mint<MEMBER>({
    iss: "did:web:example.com:<member>:issuer",
    iss_key: kp.iss_key,
    privateKey: kp.privateKey,
    subject: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    body: { /* fill in per spec §4.2 */ },
    profile: "<member>.test.v1",
  });
  assert.ok(receipt);
  // TODO: assert v=2, claim_type, signature validity, etc.
});

test("mint<MEMBER>: TSA opt-in produces valid tsa block", async () => {
  // TODO
});

test("mint<MEMBER>: getNextStatusIndex callback wires credentialStatus", async () => {
  // TODO
});
