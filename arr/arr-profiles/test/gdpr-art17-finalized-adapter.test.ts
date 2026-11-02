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

const TSA_STUB = {
  v: 1 as const,
  tsr: "base64url",
  alg: "sha-256" as const,
  tsa_url: "https://tsa.example",
  tsa_cert_chain_sha256: ["sha256:" + "a".repeat(64)],
  issued_at: "2026-05-17T12:00:00Z",
};

/** Minimal v=2 Envelope: `kind` and `tsa` live on the envelope, not the body. */
function env(claim_type: string, tsa: typeof TSA_STUB | null): Envelope {
  return { v: 2, claim_type, tsa, body: {} } as unknown as Envelope;
}

const STUB_ENVELOPE = env("ar.erasure.v1", TSA_STUB);
const BODY = {};

// ── profile_id ───────────────────────────────────────────────────────────────

test("validateGdprArt17ErasureFinalizedProfile profile_id matches the exported constant", () => {
  const ctx: ProfileValidatorCtx = { tsa_state: "tsa_verified" };
  const r = validateGdprArt17ErasureFinalizedProfile(STUB_ENVELOPE, BODY, ctx);
  assert.equal(r.profile_id, GDPR_ART17_ERASURE_FINALIZED_PROFILE_ID);
  assert.equal(GDPR_ART17_ERASURE_FINALIZED_PROFILE_ID, "arr.gdpr.art17.erasure-finalized");
});

// ── happy path ───────────────────────────────────────────────────────────────

test("validateGdprArt17ErasureFinalizedProfile returns ok=true on verified TSA + erasure kind", () => {
  const ctx: ProfileValidatorCtx = { tsa_state: "tsa_verified" };
  const r = validateGdprArt17ErasureFinalizedProfile(STUB_ENVELOPE, BODY, ctx);
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
  assert.equal("reason" in r, false);
});

// ── wrong kind ───────────────────────────────────────────────────────────────

test("validateGdprArt17ErasureFinalizedProfile returns claim_type_mismatch when kind is wrong", () => {
  const ctx: ProfileValidatorCtx = { tsa_state: "tsa_verified" };
  const r = validateGdprArt17ErasureFinalizedProfile(env("ar.consent.v1", TSA_STUB), BODY, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "claim_type_mismatch");
});

// ── missing tsa ──────────────────────────────────────────────────────────────

test("validateGdprArt17ErasureFinalizedProfile returns tsa_required_by_profile when receipt.tsa is null", () => {
  const ctx: ProfileValidatorCtx = { tsa_state: "tsa_verified" };
  const r = validateGdprArt17ErasureFinalizedProfile(env("ar.erasure.v1", null), BODY, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_required_by_profile");
});

// ── tsa_state default ────────────────────────────────────────────────────────

test("validateGdprArt17ErasureFinalizedProfile defaults tsa_state to tsa_absent and reports tsa_failed", () => {
  const ctx: ProfileValidatorCtx = {};
  const r = validateGdprArt17ErasureFinalizedProfile(STUB_ENVELOPE, BODY, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_failed:tsa_absent");
});

// ── v=2 shape: fields come from the signed envelope, never the body ─────────

test("validateGdprArt17ErasureFinalizedProfile ignores a body that claims kind/tsa the envelope lacks", () => {
  const ctx: ProfileValidatorCtx = { tsa_state: "tsa_verified" };
  const spoof = { kind: "ar.erasure.v1", tsa: TSA_STUB };
  assert.equal(
    validateGdprArt17ErasureFinalizedProfile(env("ar.consent.v1", TSA_STUB), spoof, ctx).reason,
    "claim_type_mismatch",
  );
  assert.equal(
    validateGdprArt17ErasureFinalizedProfile(env("ar.erasure.v1", null), spoof, ctx).reason,
    "tsa_required_by_profile",
  );
});
