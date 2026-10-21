import { test } from "node:test";
import assert from "node:assert/strict";
import { traceFamily } from "../src/family.ts";

test("family serves both claim types", () => {
  assert.ok(traceFamily.meta.claim_types.includes("ar.trace.v1"));
  assert.ok(traceFamily.meta.claim_types.includes("ar.trace.v2"));
  assert.equal(traceFamily.meta.subject_presence, "must-be-null");
  assert.equal(traceFamily.meta.status_list_slot, null);
});
