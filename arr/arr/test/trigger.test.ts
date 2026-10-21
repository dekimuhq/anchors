import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveTriggerReceipt } from "../src/index.ts";

test("resolver returns ACR withdrawal receipt for valid hash", async () => {
  const stubAcr = {
    kind: "ar.withdrawal.v1",
    iss: "did:web:bank.example",
    granted_at: "2026-04-30T10:00:00Z",
  };
  const out = await resolveTriggerReceipt({
    triggerReceiptHash: "sha256:" + "ab".repeat(32),
    expectedIssuer: "did:web:bank.example",
    resolver: async () => stubAcr,
  });
  assert.equal(out.valid, true);
  assert.equal(out.resolved?.kind, "ar.withdrawal.v1");
});

test("resolver returns null -> invalid", async () => {
  const out = await resolveTriggerReceipt({
    triggerReceiptHash: "sha256:" + "ab".repeat(32),
    expectedIssuer: "did:web:bank.example",
    resolver: async () => null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("trigger_receipt.not_found"));
});

test("resolved receipt has different issuer -> invalid", async () => {
  const out = await resolveTriggerReceipt({
    triggerReceiptHash: "sha256:" + "ab".repeat(32),
    expectedIssuer: "did:web:bank.example",
    resolver: async () => ({
      kind: "ar.withdrawal.v1",
      iss: "did:web:other.example",
      granted_at: "2026-04-30T10:00:00Z",
    }),
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("trigger_receipt.issuer_mismatch"));
});

test("non-acr.withdrawal kind for subject_request -> invalid", async () => {
  const out = await resolveTriggerReceipt({
    triggerReceiptHash: "sha256:" + "ab".repeat(32),
    expectedIssuer: "did:web:bank.example",
    expectedKinds: ["ar.withdrawal.v1", "ar.modification.v1"],
    resolver: async () => ({
      kind: "ar.provenance.v1",
      iss: "did:web:bank.example",
    }),
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("trigger_receipt.kind_unexpected"));
});
