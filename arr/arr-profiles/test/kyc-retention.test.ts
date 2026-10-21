import { test } from "node:test";
import assert from "node:assert/strict";
import { validateKycRetention } from "../src/index.ts";

function base(overrides: Record<string, unknown> = {}) {
  return {
    kind: "ar.expiry.v1",
    profile: "kyc.retention",
    trigger: "scheduled",
    target_kind: "subject",
    customer_commit: "sha256:" + "11".repeat(32),
    relationship_end_at: "2019-01-01T00:00:00Z",
    risk_profile_hash: "sha256:" + "22".repeat(32),
    event_at: "2024-06-01T00:00:00Z",
    ...overrides,
  };
}

test("expiry 5+ years after relationship_end passes", () => {
  const out = validateKycRetention(base() as never);
  assert.deepEqual(out.errors, []);
});

test("expiry before 5-year minimum fails", () => {
  const out = validateKycRetention(base({ event_at: "2022-01-01T00:00:00Z" }) as never);
  assert.ok(out.errors.includes("kyc.retention.min_period.violated"));
});

test("batch is permitted under kyc (unpinned)", () => {
  const out = validateKycRetention(base({ kind: "ar.batch.v1" }) as never);
  assert.equal(out.errors.includes("kyc.retention.min_period.violated"), false);
});
