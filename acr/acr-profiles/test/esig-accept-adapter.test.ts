/**
 * Tests for the esig.accept@qes universal-signature adapter.
 *
 * Phase E Task E.2.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import type { ProfileValidatorCtx } from "@dekimuhq/anchors-envelope";
import {
  validateEsigAcceptQesProfile,
  ESIG_ACCEPT_QES_PROFILE_ID,
} from "../src/esig-accept-adapter.ts";
import { ESIG_ACCEPT_QES_DESCRIPTOR } from "../src/esig-accept.ts";
import type { EsigAcceptQesReceipt } from "../src/esig-accept.ts";

const VALID_POLICY_OID = ESIG_ACCEPT_QES_DESCRIPTOR.requires_tsa_policy_oid!;

const TSA_STUB = {
  v: 1 as const,
  tsr: "base64url",
  alg: "sha-256" as const,
  tsa_url: "https://tsa.example",
  tsa_cert_chain_sha256: ["sha256:" + "a".repeat(64)],
  issued_at: "2026-05-17T12:00:00Z",
};

const RECEIPT_WITH_TSA: EsigAcceptQesReceipt = { tsa: TSA_STUB };
const RECEIPT_NO_TSA: EsigAcceptQesReceipt = { tsa: null };

/** Minimal Envelope-shaped object — adapter ignores the envelope argument. */
const STUB_ENVELOPE = { v: 2 } as unknown as Envelope;

// ── profile_id matches exported constant ─────────────────────────────────────

test("validateEsigAcceptQesProfile exposes profile_id matching the exported constant", () => {
  const ctx: ProfileValidatorCtx = {
    tsa_state: "tsa_verified",
    tsa_listed: true,
    tsa_policy_oid: VALID_POLICY_OID,
  };
  const r = validateEsigAcceptQesProfile(STUB_ENVELOPE, RECEIPT_WITH_TSA, ctx);
  assert.equal(r.profile_id, ESIG_ACCEPT_QES_PROFILE_ID);
  assert.equal(ESIG_ACCEPT_QES_PROFILE_ID, "acr.esig.accept@qes");
});

// ── happy path ───────────────────────────────────────────────────────────────

test("validateEsigAcceptQesProfile returns ok=true on verified+listed+matching OID, no reason key", () => {
  const ctx: ProfileValidatorCtx = {
    tsa_state: "tsa_verified",
    tsa_listed: true,
    tsa_policy_oid: VALID_POLICY_OID,
  };
  const r = validateEsigAcceptQesProfile(STUB_ENVELOPE, RECEIPT_WITH_TSA, ctx);
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
  assert.equal("reason" in r, false);
});

// ── missing tsa ──────────────────────────────────────────────────────────────

test("validateEsigAcceptQesProfile forwards tsa_required_by_profile reason when body.tsa is null", () => {
  const ctx: ProfileValidatorCtx = {
    tsa_state: "tsa_verified",
    tsa_listed: true,
    tsa_policy_oid: VALID_POLICY_OID,
  };
  const r = validateEsigAcceptQesProfile(STUB_ENVELOPE, RECEIPT_NO_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_required_by_profile");
});

// ── non-listed TSA ───────────────────────────────────────────────────────────

test("validateEsigAcceptQesProfile forwards tsa_listed_required_by_profile when tsa_listed=false", () => {
  const ctx: ProfileValidatorCtx = {
    tsa_state: "tsa_verified",
    tsa_listed: false,
    tsa_policy_oid: VALID_POLICY_OID,
  };
  const r = validateEsigAcceptQesProfile(STUB_ENVELOPE, RECEIPT_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_listed_required_by_profile");
});

// ── wrong policy OID ─────────────────────────────────────────────────────────

test("validateEsigAcceptQesProfile forwards tsa_policy_oid_mismatch when ctx OID differs", () => {
  const ctx: ProfileValidatorCtx = {
    tsa_state: "tsa_verified",
    tsa_listed: true,
    tsa_policy_oid: "1.2.999.placeholder",
  };
  const r = validateEsigAcceptQesProfile(STUB_ENVELOPE, RECEIPT_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_policy_oid_mismatch");
});

// ── missing tsa_state defaults to tsa_absent ─────────────────────────────────

test("validateEsigAcceptQesProfile defaults tsa_state to tsa_absent when ctx omits it", () => {
  const ctx: ProfileValidatorCtx = {
    tsa_listed: true,
    tsa_policy_oid: VALID_POLICY_OID,
  };
  const r = validateEsigAcceptQesProfile(STUB_ENVELOPE, RECEIPT_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_failed:tsa_absent");
});
