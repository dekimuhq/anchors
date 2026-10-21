import { test } from "node:test";
import assert from "node:assert/strict";
import { validateAiActArt14 } from "../src/aiact-art14.ts";
import type { ACRReceipt } from "@dekimuhq/acr-profiles/body-types";

function base(overrides: Partial<ACRReceipt> = {}): ACRReceipt {
  return {
    kind: "ar.consent.v1",
    profile: "aiact.art14",
    iss: "did:web:bank.example",
    iss_key: "ed25519:x",
    sub_commit: "sha256:" + "a".repeat(64),
    purposes: ["sha256:" + "b".repeat(64)],
    lawful_basis: "approved|sha256:apr-hash-placeholder|sha256:role-commit",
    policy_hash: "sha256:" + "c".repeat(64),
    granted_at: "2026-05-15T10:00:00Z",
    prev: null,
    field_root: "sha256:" + "d".repeat(64),
    anchor: null,
    sig: "ed25519:sig",
    countersig: null,
    qts_attestation_hash: null,
    ...overrides,
  };
}

test("validateAiActArt14 accepts each allowed oversight action", () => {
  for (const action of ["approved", "rejected", "escalated", "overridden"]) {
    const r = base({
      lawful_basis: `${action}|sha256:${"e".repeat(64)}|sha256:${"f".repeat(64)}`,
    });
    assert.equal(validateAiActArt14(r).valid, true, `should accept ${action}`);
  }
});

test("validateAiActArt14 rejects unknown oversight action", () => {
  const r = base({
    lawful_basis: `pending|sha256:${"e".repeat(64)}|sha256:${"f".repeat(64)}`,
  });
  const result = validateAiActArt14(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("oversight_action")));
});

test("validateAiActArt14 requires valid sha256 for APR receipt hash", () => {
  const r = base({ lawful_basis: `approved|not-a-hash|sha256:${"f".repeat(64)}` });
  const result = validateAiActArt14(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("apr_receipt_hash")));
});

test("validateAiActArt14 rejects wrong profile", () => {
  const r = base({ profile: "gdpr.art7" });
  const result = validateAiActArt14(r);
  assert.equal(result.valid, false);
});
