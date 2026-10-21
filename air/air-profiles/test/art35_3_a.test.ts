import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  ART35_3_A_PROFILE_ID,
  AIR_PROFILE_WARNING_CODES,
  validateImpactArt35_3_a,
} from "../src/index.ts";
import {
  allNonCompletedBodies,
  completedBody,
} from "./_helpers/bodies.ts";

const IAT = "2026-01-01T00:00:00Z";

test("art35_3_a: profile id literal", () => {
  assert.equal(ART35_3_A_PROFILE_ID, "impact.art35_3_a_automated_decisions");
});

test("art35_3_a: completed with non-empty aer + 12mo review → clean", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0AERTEST"],
      review_due_at: "2026-12-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: completed with null aer → warns missing", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({ aer_receipt_ids: null }),
    iat: IAT,
  });
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, [AIR_PROFILE_WARNING_CODES.ART35_3A_AER_LINK_MISSING]);
});

test("art35_3_a: completed with empty aer array → warns missing", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({ aer_receipt_ids: [] }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [AIR_PROFILE_WARNING_CODES.ART35_3A_AER_LINK_MISSING]);
});

test("art35_3_a: aer array with empty string entry → warns missing", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({ aer_receipt_ids: [""] }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [AIR_PROFILE_WARNING_CODES.ART35_3A_AER_LINK_MISSING]);
});

test("art35_3_a: aer array with multiple ids → clean", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0A", "01J0B", "01J0C"],
      review_due_at: "2026-06-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: 13-month review window → warns review_window_long", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0A"],
      review_due_at: "2027-02-15T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [AIR_PROFILE_WARNING_CODES.REVIEW_WINDOW_LONG]);
});

test("art35_3_a: 24-month review window → warns review_window_long", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0A"],
      review_due_at: "2028-01-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [AIR_PROFILE_WARNING_CODES.REVIEW_WINDOW_LONG]);
});

test("art35_3_a: exactly 12 months review window → no warning", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0A"],
      review_due_at: "2027-01-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: 6-month review window → clean", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0A"],
      review_due_at: "2026-07-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: same-day review (zero window) → clean", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0A"],
      review_due_at: IAT,
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: long window AND missing aer → both warnings", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: null,
      review_due_at: "2028-01-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.equal(r.warnings.length, 2);
  assert.ok(
    r.warnings.includes(AIR_PROFILE_WARNING_CODES.ART35_3A_AER_LINK_MISSING),
  );
  assert.ok(r.warnings.includes(AIR_PROFILE_WARNING_CODES.REVIEW_WINDOW_LONG));
});

test("art35_3_a: iat=null skips review-window check", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0A"],
      review_due_at: "2050-01-01T00:00:00Z",
    }),
    iat: null,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: garbage iat skips review-window check", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0A"],
      review_due_at: "2050-01-01T00:00:00Z",
    }),
    iat: "not-a-date",
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: garbage review_due_at skips window check", () => {
  // The body verifier rejects this shape; the profile validator must not
  // throw when handed it, just decline to emit the window warning.
  const body = completedBody({ aer_receipt_ids: ["01J0A"] });
  // deliberately overwrite the field with garbage
  (body as { review_due_at: string }).review_due_at = "not-a-date";
  const r = validateImpactArt35_3_a({ body, iat: IAT });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: aer with whitespace string still counts as present", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: [" "],
      review_due_at: "2026-06-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: non-completed events emit no warnings", () => {
  for (const body of allNonCompletedBodies()) {
    const r = validateImpactArt35_3_a({ body, iat: IAT });
    assert.equal(r.valid, true, `event_type=${body.event_type}`);
    assert.deepEqual(r.errors, [], `event_type=${body.event_type}`);
    assert.deepEqual(r.warnings, [], `event_type=${body.event_type}`);
  }
});

test("art35_3_a: returns a fresh array each call (no shared mutation)", () => {
  const a = validateImpactArt35_3_a({
    body: completedBody({ aer_receipt_ids: null }),
    iat: IAT,
  });
  const b = validateImpactArt35_3_a({
    body: completedBody({ aer_receipt_ids: ["01J0A"] }),
    iat: IAT,
  });
  assert.notEqual(a.warnings, b.warnings);
  assert.deepEqual(a.warnings, [AIR_PROFILE_WARNING_CODES.ART35_3A_AER_LINK_MISSING]);
  assert.deepEqual(b.warnings, []);
});

test("art35_3_a: low-risk completed still warns on missing aer", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      residual_risk_level: "low",
      aer_receipt_ids: null,
      review_due_at: "2026-06-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [AIR_PROFILE_WARNING_CODES.ART35_3A_AER_LINK_MISSING]);
});

test("art35_3_a: high-risk completed with aer set → clean", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      residual_risk_level: "high",
      aer_receipt_ids: ["01J0A"],
      review_due_at: "2026-06-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: review window negative (review before iat) → clean", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0A"],
      review_due_at: "2025-01-01T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: review window 365 days → no warning", () => {
  // 365 * 86_400_000 < 12 * AIR_MONTH_MS (≈ 12 * 30.4375 days = 365.25 days)
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: ["01J0A"],
      review_due_at: "2026-12-31T00:00:00Z",
    }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("art35_3_a: warnings field is mutable but independent across calls", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({ aer_receipt_ids: null }),
    iat: IAT,
  });
  r.warnings.push("test-mutation");
  const r2 = validateImpactArt35_3_a({
    body: completedBody({ aer_receipt_ids: null }),
    iat: IAT,
  });
  assert.equal(r2.warnings.length, 1);
  assert.ok(!r2.warnings.includes("test-mutation"));
});

test("art35_3_a: errors array is always empty on v1 surfaces", () => {
  const r1 = validateImpactArt35_3_a({
    body: completedBody({ aer_receipt_ids: null }),
    iat: IAT,
  });
  const r2 = validateImpactArt35_3_a({
    body: completedBody({ aer_receipt_ids: ["x"] }),
    iat: null,
  });
  assert.deepEqual(r1.errors, []);
  assert.deepEqual(r2.errors, []);
});

test("art35_3_a: valid flag tracks errors not warnings", () => {
  const r = validateImpactArt35_3_a({
    body: completedBody({
      aer_receipt_ids: null,
      review_due_at: "2050-01-01T00:00:00Z",
    }),
    iat: IAT,
  });
  // Two warnings, zero errors → still valid.
  assert.equal(r.valid, true);
  assert.equal(r.warnings.length, 2);
});
