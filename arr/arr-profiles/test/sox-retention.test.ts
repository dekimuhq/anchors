import { test } from "node:test";
import assert from "node:assert/strict";
import { validateSoxRetention } from "../src/index.ts";

function base(overrides: Record<string, unknown> = {}) {
  return {
    kind: "ar.expiry.v1",
    profile: "sox.retention",
    trigger: "scheduled",
    target_kind: "artifact",
    audit_record_commit: "sha256:" + "11".repeat(32),
    fiscal_period: "FY2017",
    record_origin_at: "2017-01-01T00:00:00Z",
    event_at: "2024-06-01T00:00:00Z",
    ...overrides,
  };
}

test("expiry 7+ years after record_origin passes", () => {
  const out = validateSoxRetention(base() as never);
  assert.deepEqual(out.errors, []);
});

test("expiry before 7-year minimum fails", () => {
  const out = validateSoxRetention(base({ event_at: "2023-06-01T00:00:00Z" }) as never);
  assert.ok(out.errors.includes("sox.retention.min_period.violated"));
});

test("missing fiscal_period -> invalid", () => {
  const out = validateSoxRetention(base({ fiscal_period: undefined }) as never);
  assert.ok(out.errors.includes("sox.retention.fiscal_period.required"));
});
