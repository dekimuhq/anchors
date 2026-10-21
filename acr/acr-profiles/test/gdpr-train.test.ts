import { test } from "node:test";
import assert from "node:assert/strict";
import { validateGdprTrain } from "../src/gdpr-train.ts";
import type { ACRReceipt } from "@dekimuhq/acr-profiles/body-types";

function baseReceipt(overrides: Partial<ACRReceipt> = {}): ACRReceipt {
  return {
    kind: "ar.consent.v1",
    profile: "gdpr.train",
    iss: "did:web:lab.example",
    iss_key: "ed25519:x",
    sub_commit: "sha256:" + "a".repeat(64),
    purposes: ["sha256:" + "b".repeat(64)],
    lawful_basis: "6(1)(a)|pretrain|sha256:" + "e".repeat(64),
    policy_hash: "sha256:" + "c".repeat(64),
    granted_at: "2026-06-20T10:00:00Z",
    prev: null,
    field_root: "sha256:" + "d".repeat(64),
    anchor: null,
    sig: "ed25519:sig",
    countersig: null,
    qts_attestation_hash: null,
    ...overrides,
  };
}

const M = "sha256:" + "e".repeat(64);

test("validateGdprTrain accepts both EDPB-blessed bases", () => {
  for (const basis of ["6(1)(a)", "6(1)(f)"]) {
    const r = baseReceipt({ lawful_basis: `${basis}|pretrain|${M}` });
    assert.equal(validateGdprTrain(r).valid, true, `should accept ${basis}`);
  }
});

test("validateGdprTrain accepts each training scope", () => {
  for (const scope of ["pretrain", "finetune", "rlhf", "eval", "all"]) {
    const r = baseReceipt({ lawful_basis: `6(1)(a)|${scope}|${M}` });
    assert.equal(validateGdprTrain(r).valid, true, `should accept ${scope}`);
  }
});

test("validateGdprTrain rejects a non-training lawful basis", () => {
  const r = baseReceipt({ lawful_basis: `6(1)(b)|pretrain|${M}` });
  const result = validateGdprTrain(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("basis")));
});

test("validateGdprTrain rejects a malformed lawful_basis (wrong part count)", () => {
  const r = baseReceipt({ lawful_basis: "6(1)(a)|pretrain" });
  const result = validateGdprTrain(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("lawful_basis")));
});

test("validateGdprTrain rejects an unknown scope", () => {
  const r = baseReceipt({ lawful_basis: `6(1)(a)|distill|${M}` });
  const result = validateGdprTrain(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("scope")));
});

test("validateGdprTrain rejects a malformed model_commit", () => {
  const r = baseReceipt({ lawful_basis: "6(1)(a)|pretrain|notahash" });
  const result = validateGdprTrain(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("model_commit")));
});

test("validateGdprTrain rejects wrong profile", () => {
  const r = baseReceipt({ profile: "gdpr.art7" });
  const result = validateGdprTrain(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("profile")));
});

test("validateGdprTrain requires at least one purpose", () => {
  const r = baseReceipt({ purposes: [] });
  const result = validateGdprTrain(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("purposes")));
});

test("validateGdprTrain requires granted_at to be RFC 3339 UTC", () => {
  const r = baseReceipt({ granted_at: "June 20, 2026" });
  const result = validateGdprTrain(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("granted_at")));
});

test("validateGdprTrain rejects a non-RFC-3339 expires_at when present", () => {
  const r = baseReceipt({ expires_at: "soon" });
  const result = validateGdprTrain(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("expires_at")));
});
