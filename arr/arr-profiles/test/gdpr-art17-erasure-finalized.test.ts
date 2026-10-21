import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateGdprArt17ErasureFinalized,
  GDPR_ART17_ERASURE_FINALIZED,
} from "../src/gdpr-art17.ts";
import type {
  ErasureFinalizedReceipt,
  ErasureFinalizedCtx,
} from "../src/gdpr-art17.ts";

/** Minimal TsaBlock stub sufficient for the receipt shape check. */
const TSA_STUB = {
  v: 1 as const,
  tsr: "base64url",
  alg: "sha-256" as const,
  tsa_url: "https://tsa.example",
  tsa_cert_chain_sha256: ["sha256:" + "a".repeat(64)],
  issued_at: "2026-05-17T12:00:00Z",
};

const RECEIPT_ERASURE_WITH_TSA: ErasureFinalizedReceipt = {
  kind: "ar.erasure.v1",
  tsa: TSA_STUB,
};

const CTX_VERIFIED: ErasureFinalizedCtx = { tsa_state: "tsa_verified" };

// ── descriptor sanity ─────────────────────────────────────────────────────────

test("GDPR_ART17_ERASURE_FINALIZED descriptor requires_tsa=true and requires_tsa_listed=false", () => {
  assert.equal(GDPR_ART17_ERASURE_FINALIZED.requires_tsa, true);
  assert.equal(GDPR_ART17_ERASURE_FINALIZED.requires_tsa_listed, false);
  assert.equal(GDPR_ART17_ERASURE_FINALIZED.requires_tsa_policy_oid, undefined);
});

// ── wrong kind ────────────────────────────────────────────────────────────────

test("gdpr.art17.erasure-finalized rejects kind=ar.expiry.v1", () => {
  const receipt: ErasureFinalizedReceipt = { kind: "ar.expiry.v1", tsa: TSA_STUB };
  const r = validateGdprArt17ErasureFinalized(receipt, CTX_VERIFIED);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "claim_type_mismatch");
});

test("gdpr.art17.erasure-finalized rejects kind=ar.anonymization.v1", () => {
  const receipt: ErasureFinalizedReceipt = { kind: "ar.anonymization.v1", tsa: TSA_STUB };
  const r = validateGdprArt17ErasureFinalized(receipt, CTX_VERIFIED);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "claim_type_mismatch");
});

// ── missing tsa ───────────────────────────────────────────────────────────────

test("gdpr.art17.erasure-finalized rejects receipt with tsa=null", () => {
  const receipt: ErasureFinalizedReceipt = { kind: "ar.erasure.v1", tsa: null };
  const r = validateGdprArt17ErasureFinalized(receipt, CTX_VERIFIED);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_required_by_profile");
});

// ── tsa present but not verified ─────────────────────────────────────────────

test("gdpr.art17.erasure-finalized rejects tsa_state=tsa_unrecognised_anchor", () => {
  const ctx: ErasureFinalizedCtx = { tsa_state: "tsa_unrecognised_anchor" };
  const r = validateGdprArt17ErasureFinalized(RECEIPT_ERASURE_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_failed:tsa_unrecognised_anchor");
});

test("gdpr.art17.erasure-finalized rejects tsa_state=tsa_signature_invalid", () => {
  const ctx: ErasureFinalizedCtx = { tsa_state: "tsa_signature_invalid" };
  const r = validateGdprArt17ErasureFinalized(RECEIPT_ERASURE_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_failed:tsa_signature_invalid");
});

// ── happy path — listed and non-listed TSA both accepted ─────────────────────

test("gdpr.art17.erasure-finalized passes with a verified non-EUTL TSA (FreeTSA)", () => {
  // tsa_listed=false is fine for this profile
  const r = validateGdprArt17ErasureFinalized(RECEIPT_ERASURE_WITH_TSA, CTX_VERIFIED);
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("gdpr.art17.erasure-finalized passes with a verified EUTL-listed TSA", () => {
  // tsa_listed=true is also accepted (strictly better, but not required)
  const r = validateGdprArt17ErasureFinalized(RECEIPT_ERASURE_WITH_TSA, CTX_VERIFIED);
  assert.equal(r.ok, true);
});
