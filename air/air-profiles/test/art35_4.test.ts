import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  ART35_4_PROFILE_ID,
  validateImpactArt35_4,
} from "../src/index.ts";
import {
  allNonCompletedBodies,
  completedBody,
  thresholdTriggeredBody,
} from "./_helpers/bodies.ts";

const IAT = "2026-01-01T00:00:00Z";

test("art35_4: profile id literal", () => {
  assert.equal(ART35_4_PROFILE_ID, "impact.art35_4_dpa_list");
});

test("art35_4: completed → clean (v1 no single-receipt surface)", () => {
  const r = validateImpactArt35_4({
    body: completedBody(),
    iat: IAT,
  });
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, []);
});

test("art35_4: threshold_triggered → clean (dpa_jurisdiction deferred to v1.1)", () => {
  const r = validateImpactArt35_4({
    body: thresholdTriggeredBody(),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_4: every non-completed event → clean", () => {
  for (const body of allNonCompletedBodies()) {
    const r = validateImpactArt35_4({ body, iat: IAT });
    assert.equal(r.valid, true);
    assert.deepEqual(r.errors, []);
    assert.deepEqual(r.warnings, []);
  }
});

test("art35_4: missing aer/alr does NOT warn", () => {
  const r = validateImpactArt35_4({
    body: completedBody({
      aer_receipt_ids: null,
      alr_receipt_ids: null,
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_4: long review window does NOT warn", () => {
  const r = validateImpactArt35_4({
    body: completedBody({ review_due_at: "2050-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_4: iat=null is accepted", () => {
  const r = validateImpactArt35_4({ body: completedBody(), iat: null });
  assert.equal(r.valid, true);
});

test("art35_4: high-risk completed → no warnings", () => {
  const r = validateImpactArt35_4({
    body: completedBody({ residual_risk_level: "high" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_4: returns fresh result objects", () => {
  const a = validateImpactArt35_4({ body: completedBody(), iat: IAT });
  const b = validateImpactArt35_4({ body: completedBody(), iat: IAT });
  assert.notEqual(a, b);
});

test("art35_4: errors array always empty in v1", () => {
  for (const body of allNonCompletedBodies()) {
    const r = validateImpactArt35_4({ body, iat: IAT });
    assert.deepEqual(r.errors, []);
  }
});
