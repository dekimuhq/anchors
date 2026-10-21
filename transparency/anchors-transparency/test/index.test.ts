import { test } from "node:test";
import assert from "node:assert/strict";
import * as api from "../src/index.ts";

test("public surface exports the documented functions", () => {
  for (const name of ["leafHash", "merkleRoot", "auditPath", "consistencyPath", "signCheckpoint", "parseCheckpoint", "verifyCheckpoint", "signPromise", "verifyPromise", "verifyInclusion", "logStatus", "verifyInclusionProof", "verifyConsistencyProof"]) {
    assert.equal(typeof (api as Record<string, unknown>)[name], "function", name);
  }
});
