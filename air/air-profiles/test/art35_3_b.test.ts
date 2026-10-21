import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  ART35_3_B_PROFILE_ID,
  AIR_PROFILE_WARNING_CODES,
  validateImpactArt35_3_b,
} from "../src/index.ts";
import {
  allNonCompletedBodies,
  completedBody,
} from "./_helpers/bodies.ts";

const IAT = "2026-01-01T00:00:00Z";

test("art35_3_b: profile id literal", () => {
  assert.equal(
    ART35_3_B_PROFILE_ID,
    "impact.art35_3_b_large_scale_special_categories",
  );
});

test("art35_3_b: completed with non-empty alr → clean", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({ alr_receipt_ids: ["01J0ALR"] }),
    iat: IAT,
  });
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, []);
});

test("art35_3_b: completed with null alr → warns missing", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({ alr_receipt_ids: null }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [AIR_PROFILE_WARNING_CODES.ART35_3B_ALR_LINK_MISSING]);
});

test("art35_3_b: completed with empty alr array → warns missing", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({ alr_receipt_ids: [] }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [AIR_PROFILE_WARNING_CODES.ART35_3B_ALR_LINK_MISSING]);
});

test("art35_3_b: completed with multiple alr ids → clean", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({ alr_receipt_ids: ["01J0A", "01J0B"] }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_b: alr containing empty string → warns missing", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({ alr_receipt_ids: ["01J0A", ""] }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [AIR_PROFILE_WARNING_CODES.ART35_3B_ALR_LINK_MISSING]);
});

test("art35_3_b: long review window does NOT warn (no §5.2 window cap)", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({
      alr_receipt_ids: ["01J0A"],
      review_due_at: "2050-01-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_b: missing aer_receipt_ids does NOT warn (§5.1 surface only)", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({
      alr_receipt_ids: ["01J0A"],
      aer_receipt_ids: null,
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_b: non-completed events emit no warnings", () => {
  for (const body of allNonCompletedBodies()) {
    const r = validateImpactArt35_3_b({ body, iat: IAT });
    assert.equal(r.valid, true);
    assert.deepEqual(r.errors, []);
    assert.deepEqual(r.warnings, []);
  }
});

test("art35_3_b: iat=null is accepted (no window check on §5.2)", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({ alr_receipt_ids: ["01J0A"] }),
    iat: null,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_b: residual_risk_level=high with alr set → clean", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({
      residual_risk_level: "high",
      alr_receipt_ids: ["01J0A"],
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_b: completed with only atr/aer/apur but no alr → warns missing", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({
      alr_receipt_ids: null,
      aer_receipt_ids: ["01J0A"],
      atr_receipt_ids: ["01J0T"],
      apur_receipt_ids: ["01J0P"],
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [AIR_PROFILE_WARNING_CODES.ART35_3B_ALR_LINK_MISSING]);
});

test("art35_3_b: returns fresh result objects across calls", () => {
  const a = validateImpactArt35_3_b({
    body: completedBody({ alr_receipt_ids: null }),
    iat: IAT,
  });
  const b = validateImpactArt35_3_b({
    body: completedBody({ alr_receipt_ids: ["x"] }),
    iat: IAT,
  });
  assert.notEqual(a, b);
  assert.notEqual(a.warnings, b.warnings);
});

test("art35_3_b: errors array always empty", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({ alr_receipt_ids: null }),
    iat: IAT,
  });
  assert.deepEqual(r.errors, []);
});

test("art35_3_b: valid flag tracks errors not warnings", () => {
  const r = validateImpactArt35_3_b({
    body: completedBody({ alr_receipt_ids: null }),
    iat: IAT,
  });
  assert.equal(r.valid, true);
  assert.equal(r.warnings.length, 1);
});
