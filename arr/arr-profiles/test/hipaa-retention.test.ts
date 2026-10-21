import { test } from "node:test";
import assert from "node:assert/strict";
import { validateHipaaRetention } from "../src/index.ts";

function base(overrides: Record<string, unknown> = {}) {
  return {
    kind: "ar.expiry.v1",
    profile: "hipaa.retention",
    trigger: "scheduled",
    target_kind: "artifact",
    covered_entity_commit: "sha256:" + "11".repeat(32),
    phi_categories: ["sha256:" + "22".repeat(32)],
    record_origin_at: "2018-01-01T00:00:00Z",
    event_at: "2024-06-01T00:00:00Z",
    effective_until: "2024-06-01T00:00:00Z",
    ...overrides,
  };
}

test("expiry 6+ years after record_origin passes", () => {
  const out = validateHipaaRetention(base() as never);
  assert.deepEqual(out.errors, []);
});

test("expiry before 6-year minimum fails", () => {
  const out = validateHipaaRetention(base({ event_at: "2023-01-01T00:00:00Z" }) as never);
  assert.ok(out.errors.includes("hipaa.retention.min_period.violated"));
});

test("erasure receipt skips the 6-year check", () => {
  const out = validateHipaaRetention(base({ kind: "ar.erasure.v1", event_at: "2023-01-01T00:00:00Z" }) as never);
  assert.deepEqual(out.errors, []);
});

test("standalone batch under hipaa.retention is invalid (Mode A required)", () => {
  const out = validateHipaaRetention(base({ kind: "ar.batch.v1" }) as never);
  assert.ok(out.errors.includes("hipaa.retention.mode_a.required"));
});

test("missing covered_entity_commit -> invalid", () => {
  const out = validateHipaaRetention(base({ covered_entity_commit: undefined }) as never);
  assert.ok(out.errors.includes("hipaa.retention.covered_entity_commit.required"));
});
