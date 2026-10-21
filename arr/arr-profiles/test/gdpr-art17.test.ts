import { test } from "node:test";
import assert from "node:assert/strict";
import { validateGdprArt17 } from "../src/index.ts";

function baseReceipt(overrides: Record<string, unknown> = {}) {
  return {
    kind: "ar.erasure.v1",
    profile: "gdpr.art17",
    trigger: "subject_request",
    trigger_receipt: "sha256:" + "ef".repeat(32),
    target_kind: "subject",
    subject_data_categories: ["sha256:" + "01".repeat(32)],
    controller_contact_hash: "sha256:" + "02".repeat(32),
    ...overrides,
  };
}

test("valid Art 17 erasure receipt passes", () => {
  const out = validateGdprArt17(baseReceipt() as never);
  assert.deepEqual(out.errors, []);
});

test("anonymization is a permitted Art 17 fulfilment alternative", () => {
  const out = validateGdprArt17(baseReceipt({ kind: "ar.anonymization.v1" }) as never);
  assert.deepEqual(out.errors, []);
});

test("ar.expiry.v1 under gdpr.art17 is invalid", () => {
  const out = validateGdprArt17(baseReceipt({ kind: "ar.expiry.v1" }) as never);
  assert.ok(out.errors.includes("gdpr.art17.kind.disallowed"));
});

test("missing subject_data_categories -> invalid", () => {
  const out = validateGdprArt17(baseReceipt({ subject_data_categories: undefined }) as never);
  assert.ok(out.errors.includes("gdpr.art17.subject_data_categories.required"));
});

test("missing controller_contact_hash -> invalid", () => {
  const out = validateGdprArt17(baseReceipt({ controller_contact_hash: undefined }) as never);
  assert.ok(out.errors.includes("gdpr.art17.controller_contact_hash.required"));
});

test("standalone ar.batch.v1 under gdpr.art17 is invalid (Mode A required)", () => {
  const out = validateGdprArt17(baseReceipt({ kind: "ar.batch.v1" }) as never);
  assert.ok(out.errors.includes("gdpr.art17.mode_a.required"));
});
