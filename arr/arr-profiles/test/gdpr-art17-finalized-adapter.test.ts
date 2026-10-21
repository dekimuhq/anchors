/**
 * Tests for the gdpr.art17.erasure-finalized universal-signature adapter.
 *
 * Phase E Task E.2.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Envelope, ProfileValidatorCtx } from "@dekimuhq/anchors-envelope";
import {
  validateGdprArt17ErasureFinalizedProfile,
  GDPR_ART17_ERASURE_FINALIZED_PROFILE_ID,
} from "../src/gdpr-art17-finalized-adapter.ts";
import type { ErasureFinalizedReceipt } from "../src/gdpr-art17.ts";

const TSA_STUB = {
  v: 1 as const,
  tsr: "base64url",
  alg: "sha-256" as const,
  tsa_url: "https://tsa.example",
  tsa_cert_chain_sha256: ["sha256:" + "a".repeat(64)],
  issued_at: "2026-05-17T12:00:00Z",
};

const RECEIPT_ERASURE: ErasureFinalizedReceipt = {
  kind: "ar.erasure.v1",
  tsa: TSA_STUB,
};

/** Minimal Envelope-shaped object — adapter ignores the envelope argument. */
const STUB_ENVELOPE = { v: 2 } as unknown as Envelope;

// ── profile_id ───────────────────────────────────────────────────────────────

test("validateGdprArt17ErasureFinalizedProfile profile_id matches the exported constant", () => {
  const ctx: ProfileValidatorCtx = { tsa_state: "tsa_verified" };
  const r = validateGdprArt17ErasureFinalizedProfile(STUB_ENVELOPE, RECEIPT_ERASURE, ctx);
  assert.equal(r.profile_id, GDPR_ART17_ERASURE_FINALIZED_PROFILE_ID);
  assert.equal(GDPR_ART17_ERASURE_FINALIZED_PROFILE_ID, "arr.gdpr.art17.erasure-finalized");
});

// ── happy path ───────────────────────────────────────────────────────────────

test("validateGdprArt17ErasureFinalizedProfile returns ok=true on verified TSA + erasure kind", () => {
  const ctx: ProfileValidatorCtx = { tsa_state: "tsa_verified" };
  const r = validateGdprArt17ErasureFinalizedProfile(STUB_ENVELOPE, RECEIPT_ERASURE, ctx);
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
  assert.equal("reason" in r, false);
});

// ── wrong kind ───────────────────────────────────────────────────────────────

test("validateGdprArt17ErasureFinalizedProfile returns claim_type_mismatch when kind is wrong", () => {
  const ctx: ProfileValidatorCtx = { tsa_state: "tsa_verified" };
  const wrong: ErasureFinalizedReceipt = { kind: "ar.consent.v1", tsa: TSA_STUB };
  const r = validateGdprArt17ErasureFinalizedProfile(STUB_ENVELOPE, wrong, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "claim_type_mismatch");
});

// ── missing tsa ──────────────────────────────────────────────────────────────

test("validateGdprArt17ErasureFinalizedProfile returns tsa_required_by_profile when receipt.tsa is null", () => {
  const ctx: ProfileValidatorCtx = { tsa_state: "tsa_verified" };
  const r = validateGdprArt17ErasureFinalizedProfile(
    STUB_ENVELOPE,
    { kind: "ar.erasure.v1", tsa: null },
    ctx,
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_required_by_profile");
});

// ── tsa_state default ────────────────────────────────────────────────────────

test("validateGdprArt17ErasureFinalizedProfile defaults tsa_state to tsa_absent and reports tsa_failed", () => {
  const ctx: ProfileValidatorCtx = {};
  const r = validateGdprArt17ErasureFinalizedProfile(STUB_ENVELOPE, RECEIPT_ERASURE, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_failed:tsa_absent");
});
