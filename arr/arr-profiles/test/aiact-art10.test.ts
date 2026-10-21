import { test } from "node:test";
import assert from "node:assert/strict";
import { validateAiActArt10 } from "../src/index.ts";

function base(overrides: Record<string, unknown> = {}) {
  return {
    kind: "ar.expiry.v1",
    profile: "aiact.art10",
    trigger: "scheduled",
    target_kind: "artifact",
    model_commit: "sha256:" + "11".repeat(32),
    dataset_commit: "sha256:" + "22".repeat(32),
    conformity_assessment_at: "2030-01-01T00:00:00Z",
    event_at: "2040-06-01T00:00:00Z",
    ...overrides,
  };
}

test("expiry 10+ years after conformity passes", () => {
  const out = validateAiActArt10(base() as never);
  assert.deepEqual(out.errors, []);
});

test("expiry before 10-year minimum fails", () => {
  const out = validateAiActArt10(base({ event_at: "2035-01-01T00:00:00Z" }) as never);
  assert.ok(out.errors.includes("aiact.art10.min_period.violated"));
});

test("conformity_assessment_at: null -> expiry permitted (indefinite retention not violated)", () => {
  const out = validateAiActArt10(base({ conformity_assessment_at: null }) as never);
  assert.ok(out.errors.includes("aiact.art10.conformity_assessment_at.unset"));
});

test("erasure skips the time-bound check", () => {
  const out = validateAiActArt10(base({ kind: "ar.erasure.v1", event_at: "2030-06-01T00:00:00Z" }) as never);
  assert.equal(out.errors.includes("aiact.art10.min_period.violated"), false);
});

test("missing model_commit -> invalid (breaks APR cross-reference)", () => {
  const out = validateAiActArt10(base({ model_commit: undefined }) as never);
  assert.ok(out.errors.includes("aiact.art10.model_commit.required"));
});
