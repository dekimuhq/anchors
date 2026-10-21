import { test } from "node:test";
import assert from "node:assert/strict";
import { complianceFamily } from "../src/family.ts";

test("family owns ar.compliance.v1 + chip 21 + must-be-null subject", () => {
  assert.deepEqual(complianceFamily.meta.claim_types, ["ar.compliance.v1"]);
  assert.equal(complianceFamily.meta.chip, 21);
  assert.equal(complianceFamily.meta.subject_presence, "must-be-null");
  assert.equal(complianceFamily.meta.status_list_slot, null);
});
