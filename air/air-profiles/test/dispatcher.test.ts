import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  AIR_PROFILE_WARNING_CODES,
  AIR_V1_PROFILES,
  ART35_3_A_PROFILE_ID,
  ART35_3_B_PROFILE_ID,
  ART35_3_C_PROFILE_ID,
  ART35_4_PROFILE_ID,
  REGISTERED_AIR_PROFILES,
  VOLUNTARY_PROFILE_ID,
  getAirProfileValidator,
  validateAirProfile,
  validateImpactArt35_3_a,
  validateImpactArt35_3_b,
  validateImpactArt35_3_c,
  validateImpactArt35_4,
  validateImpactVoluntary,
} from "../src/index.ts";
import { completedBody } from "./_helpers/bodies.ts";

const IAT = "2026-01-01T00:00:00Z";

test("dispatcher: REGISTERED_AIR_PROFILES has all five v1 profile ids", () => {
  assert.equal(REGISTERED_AIR_PROFILES.length, 5);
  assert.ok(REGISTERED_AIR_PROFILES.includes(ART35_3_A_PROFILE_ID));
  assert.ok(REGISTERED_AIR_PROFILES.includes(ART35_3_B_PROFILE_ID));
  assert.ok(REGISTERED_AIR_PROFILES.includes(ART35_3_C_PROFILE_ID));
  assert.ok(REGISTERED_AIR_PROFILES.includes(ART35_4_PROFILE_ID));
  assert.ok(REGISTERED_AIR_PROFILES.includes(VOLUNTARY_PROFILE_ID));
});

test("dispatcher: AIR_V1_PROFILES matches REGISTERED_AIR_PROFILES set-wise", () => {
  const a = new Set(AIR_V1_PROFILES);
  const b = new Set(REGISTERED_AIR_PROFILES);
  assert.equal(a.size, b.size);
  for (const id of a) assert.ok(b.has(id));
});

test("dispatcher: dispatches art35_3_a to its validator", () => {
  const body = completedBody({ aer_receipt_ids: null });
  const r = validateAirProfile(ART35_3_A_PROFILE_ID, { body, iat: IAT });
  assert.deepEqual(r.warnings, [
    AIR_PROFILE_WARNING_CODES.ART35_3A_AER_LINK_MISSING,
  ]);
});

test("dispatcher: dispatches art35_3_b to its validator", () => {
  const body = completedBody({ alr_receipt_ids: null });
  const r = validateAirProfile(ART35_3_B_PROFILE_ID, { body, iat: IAT });
  assert.deepEqual(r.warnings, [
    AIR_PROFILE_WARNING_CODES.ART35_3B_ALR_LINK_MISSING,
  ]);
});

test("dispatcher: dispatches art35_3_c to its validator (no-op)", () => {
  const r = validateAirProfile(ART35_3_C_PROFILE_ID, {
    body: completedBody({ alr_receipt_ids: null }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("dispatcher: dispatches art35_4 to its validator (no-op)", () => {
  const r = validateAirProfile(ART35_4_PROFILE_ID, {
    body: completedBody(),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, []);
});

test("dispatcher: dispatches voluntary to its validator", () => {
  const r = validateAirProfile(VOLUNTARY_PROFILE_ID, {
    body: completedBody({ review_due_at: "2050-01-01T00:00:00Z" }),
    iat: IAT,
  });
  assert.deepEqual(r.warnings, [
    AIR_PROFILE_WARNING_CODES.REVIEW_WINDOW_LONG_VOLUNTARY,
  ]);
});

test("dispatcher: unknown profile string → profile.unknown error", () => {
  const r = validateAirProfile("impact.unknown", {
    body: completedBody(),
    iat: IAT,
  });
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["profile.unknown"]);
  assert.deepEqual(r.warnings, []);
});

test("dispatcher: empty profile string → profile.unknown error", () => {
  const r = validateAirProfile("", {
    body: completedBody(),
    iat: IAT,
  });
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["profile.unknown"]);
});

test("dispatcher: typo on a real profile id → profile.unknown error", () => {
  const r = validateAirProfile("impact.art35_3_x_typo", {
    body: completedBody(),
    iat: IAT,
  });
  assert.deepEqual(r.errors, ["profile.unknown"]);
});

test("dispatcher: getAirProfileValidator returns each registered fn", () => {
  assert.equal(
    getAirProfileValidator(ART35_3_A_PROFILE_ID),
    validateImpactArt35_3_a,
  );
  assert.equal(
    getAirProfileValidator(ART35_3_B_PROFILE_ID),
    validateImpactArt35_3_b,
  );
  assert.equal(
    getAirProfileValidator(ART35_3_C_PROFILE_ID),
    validateImpactArt35_3_c,
  );
  assert.equal(
    getAirProfileValidator(ART35_4_PROFILE_ID),
    validateImpactArt35_4,
  );
  assert.equal(
    getAirProfileValidator(VOLUNTARY_PROFILE_ID),
    validateImpactVoluntary,
  );
});

test("dispatcher: getAirProfileValidator(unknown) returns undefined", () => {
  assert.equal(
    // @ts-expect-error — testing unknown literal at runtime
    getAirProfileValidator("impact.unknown"),
    undefined,
  );
});

test("dispatcher: every registered profile validates a minimal completed body", () => {
  for (const profile of REGISTERED_AIR_PROFILES) {
    const r = validateAirProfile(profile, {
      body: completedBody({
        aer_receipt_ids: ["01J0A"],
        alr_receipt_ids: ["01J0L"],
        review_due_at: "2027-01-01T00:00:00Z",
      }),
      iat: IAT,
    });
    assert.equal(r.valid, true, `profile=${profile}`);
    assert.deepEqual(r.errors, [], `profile=${profile}`);
    assert.deepEqual(r.warnings, [], `profile=${profile}`);
  }
});

test("dispatcher: every registered profile is callable via getAirProfileValidator", () => {
  for (const profile of REGISTERED_AIR_PROFILES) {
    const fn = getAirProfileValidator(profile);
    assert.equal(typeof fn, "function", `profile=${profile}`);
    const r = fn!({
      body: completedBody({
        aer_receipt_ids: ["x"],
        alr_receipt_ids: ["x"],
        review_due_at: "2027-01-01T00:00:00Z",
      }),
      iat: IAT,
    });
    assert.equal(r.valid, true);
  }
});

test("dispatcher: result objects from dispatcher are not shared across calls", () => {
  const a = validateAirProfile(ART35_3_A_PROFILE_ID, {
    body: completedBody({ aer_receipt_ids: null }),
    iat: IAT,
  });
  const b = validateAirProfile(ART35_3_A_PROFILE_ID, {
    body: completedBody({ aer_receipt_ids: null }),
    iat: IAT,
  });
  assert.notEqual(a, b);
  assert.notEqual(a.warnings, b.warnings);
});
