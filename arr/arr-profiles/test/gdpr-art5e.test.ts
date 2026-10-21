import { test } from "node:test";
import assert from "node:assert/strict";
import { validateGdprArt5e } from "../src/index.ts";

function baseReceipt(overrides: Record<string, unknown> = {}) {
  return {
    kind: "ar.expiry.v1",
    profile: "gdpr.art5e",
    trigger: "scheduled",
    target_kind: "subject",
    retention_basis_commit: "sha256:" + "11".repeat(32),
    original_collection_at: "2020-01-01T00:00:00Z",
    ...overrides,
  };
}

test("expiry passes", () => {
  const out = validateGdprArt5e(baseReceipt() as never);
  assert.deepEqual(out.errors, []);
});

test("batch under art5e is permitted (Mode B)", () => {
  const out = validateGdprArt5e(baseReceipt({ kind: "ar.batch.v1", batch_event_kind: "ar.expiry.v1" }) as never);
  assert.deepEqual(out.errors, []);
});

test("subject_request trigger is disallowed under art5e", () => {
  const out = validateGdprArt5e(baseReceipt({ trigger: "subject_request" }) as never);
  assert.ok(out.errors.includes("gdpr.art5e.trigger.disallowed"));
});

test("missing retention_basis_commit -> invalid", () => {
  const out = validateGdprArt5e(baseReceipt({ retention_basis_commit: undefined }) as never);
  assert.ok(out.errors.includes("gdpr.art5e.retention_basis_commit.required"));
});

test("ar.erasure.v1 under art5e is invalid", () => {
  const out = validateGdprArt5e(baseReceipt({ kind: "ar.erasure.v1" }) as never);
  assert.ok(out.errors.includes("gdpr.art5e.kind.disallowed"));
});
