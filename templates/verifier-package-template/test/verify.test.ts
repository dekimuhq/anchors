// @dekimuhq/<member>-verifier — verify test scaffold
//
// TDD: write failing tests for each acceptance criterion in the spec's §4 body
// schema and §6 verifier semantics BEFORE writing src/verify.ts implementation.

import { test } from "node:test";
import assert from "node:assert/strict";
import { verify<MEMBER> } from "../src/index.ts";

test("verify<MEMBER>: valid v=2 envelope passes", async () => {
  // TODO: load a known-good test vector
  const receipt = { /* paste a valid receipt here */ };
  const result = await verify<MEMBER>(receipt as never, {
    trustedIssuers: [],
    resolveStatusList: async () => null,
    resolveAnchor: async () => null,
  });
  assert.equal(result.ok, true);
});

test("verify<MEMBER>: missing required body field fails with schema_invalid", async () => {
  // TODO
});

test("verify<MEMBER>: chain prev resolution failure surfaces chain.prev_unresolved", async () => {
  // TODO
});

// TODO: one test per spec §6.2 error code.
