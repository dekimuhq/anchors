import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  AIR_PROFILE_WARNING_CODES,
  VOLUNTARY_PROFILE_ID,
  validateImpactVoluntary,
} from "../src/index.ts";
import {
  allNonCompletedBodies,
  completedBody,
} from "./_helpers/bodies.ts";

const IAT = "2026-01-01T00:00:00Z";

test("voluntary: profile id literal", () => {
  assert.equal(VOLUNTARY_PROFILE_ID, "impact.voluntary");
});

test("voluntary: 12-month review window → clean", () => {
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2027-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, []);
});

test("voluntary: 24-month review window → clean (still ≤36)", () => {
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2028-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("voluntary: ~35-month review window → clean (under 36mo cap)", () => {
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2028-11-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("voluntary: 48-month review window → warns review_window_long_voluntary", () => {
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2030-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [
    AIR_PROFILE_WARNING_CODES.REVIEW_WINDOW_LONG_VOLUNTARY,
  ]);
});

test("voluntary: 10-year review window → warns", () => {
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2036-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [
    AIR_PROFILE_WARNING_CODES.REVIEW_WINDOW_LONG_VOLUNTARY,
  ]);
});

test("voluntary: missing aer does NOT warn (no §5.1 surface)", () => {
  const r = validateImpactVoluntary({
    body: completedBody({
      aer_receipt_ids: null,
      review_due_at: "2027-01-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("voluntary: missing alr does NOT warn (no §5.2 surface)", () => {
  const r = validateImpactVoluntary({
    body: completedBody({
      alr_receipt_ids: null,
      review_due_at: "2027-01-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("voluntary: non-completed events emit no warnings", () => {
  for (const body of allNonCompletedBodies()) {
    const r = validateImpactVoluntary({ body, iat: IAT });
    assert.equal(r.valid, true);
    assert.deepEqual(r.errors, []);
    assert.deepEqual(r.warnings, []);
  }
});

test("voluntary: iat=null skips review-window check", () => {
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2050-01-01T00:00:00Z" }),
    iat: null,
  });
  assert.deepEqual(r.warnings, []);
});

test("voluntary: garbage iat skips review-window check", () => {
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2050-01-01T00:00:00Z" }),
    iat: "garbage",
  });
  assert.deepEqual(r.warnings, []);
});

test("voluntary: garbage review_due_at skips window check", () => {
  const body = completedBody();
  (body as { review_due_at: string }).review_due_at = "not-a-date";
  const r = validateImpactVoluntary({ body, iat: IAT });
  assert.deepEqual(r.warnings, []);
});

test("voluntary: negative window (review before iat) → clean", () => {
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2025-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("voluntary: same-day review → clean", () => {
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: IAT }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("voluntary: returns fresh result per call", () => {
  const a = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2050-01-01T00:00:00Z" }),
    iat: IAT,
  });
  const b = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2027-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.notEqual(a.warnings, b.warnings);
  assert.equal(a.warnings.length, 1);
  assert.equal(b.warnings.length, 0);
});

test("voluntary: high-risk residual still no chain-walker warning here", () => {
  // §5.5 chain-level surface `voluntary_high_risk_no_consultation` lives in
  // air-verifier chain walker, not in the single-receipt validator.
  const r = validateImpactVoluntary({
    body: completedBody({
      residual_risk_level: "high",
      review_due_at: "2027-01-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("voluntary: errors array always empty in v1", () => {
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2050-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.deepEqual(r.errors, []);
  assert.equal(r.valid, true);
});

test("voluntary: warning surface narrower than strict 12mo window", () => {
  // 24-month window would trip §5.1 (strict) but NOT §5.5 (voluntary).
  const r = validateImpactVoluntary({
    body: completedBody({ review_due_at: "2028-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});
