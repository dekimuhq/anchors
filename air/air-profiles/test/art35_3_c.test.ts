import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  ART35_3_C_PROFILE_ID,
  validateImpactArt35_3_c,
} from "../src/index.ts";
import {
  allNonCompletedBodies,
  completedBody,
} from "./_helpers/bodies.ts";

const IAT = "2026-01-01T00:00:00Z";

test("art35_3_c: profile id literal", () => {
  assert.equal(ART35_3_C_PROFILE_ID, "impact.art35_3_c_public_monitoring");
});

test("art35_3_c: completed with alr → clean (alr is MAY-grade not SHOULD)", () => {
  const r = validateImpactArt35_3_c({
    body: completedBody({ alr_receipt_ids: ["01J0A"] }),
    iat: IAT,
  });
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, []);
});

test("art35_3_c: completed with null alr → still clean (MAY-grade)", () => {
  const r = validateImpactArt35_3_c({
    body: completedBody({ alr_receipt_ids: null }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_c: completed with empty alr array → still clean", () => {
  const r = validateImpactArt35_3_c({
    body: completedBody({ alr_receipt_ids: [] }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_c: missing aer does NOT warn (§5.1 surface only)", () => {
  const r = validateImpactArt35_3_c({
    body: completedBody({ aer_receipt_ids: null }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_c: long review window does NOT warn", () => {
  const r = validateImpactArt35_3_c({
    body: completedBody({ review_due_at: "2050-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_c: non-completed events emit no warnings", () => {
  for (const body of allNonCompletedBodies()) {
    const r = validateImpactArt35_3_c({ body, iat: IAT });
    assert.equal(r.valid, true);
    assert.deepEqual(r.errors, []);
    assert.deepEqual(r.warnings, []);
  }
});

test("art35_3_c: iat=null is accepted", () => {
  const r = validateImpactArt35_3_c({
    body: completedBody(),
    iat: null,
  });
  assert.equal(r.valid, true);
});

test("art35_3_c: high-risk completed → no warnings (chain-level concern)", () => {
  const r = validateImpactArt35_3_c({
    body: completedBody({ residual_risk_level: "high" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_c: returns fresh objects per call", () => {
  const a = validateImpactArt35_3_c({ body: completedBody(), iat: IAT });
  const b = validateImpactArt35_3_c({ body: completedBody(), iat: IAT });
  assert.notEqual(a, b);
});
