/**
 * TSA mandate integration — mint → verify round-trip for AAR's event+service_type
 * keyed TSA mandate (FAMILY-CONSISTENCY §2). Sister of the per-event matrix tests
 * in abr/air/anr/alr-verifier.
 *
 * AAR's mandate is body-keyed (issuance+qts MANDATORY, else RECOMMENDED), not
 * profile-keyed, so it is enforced as a post-step (`applyAarTsaMandate`) inside
 * `aar-verifier`'s `verifyReceipt` rather than via the factory's profile-keyed
 * `tsa_mandate` map. This test exists because that wiring was previously absent —
 * `applyAarTsaMandate` was exported but never called, so a qts-issuance receipt
 * with no TSA block verified as valid instead of hard-failing.
 *
 * Coverage:
 *   M1 — issuance + service_type=qts, tsa absent → signature_valid:false,
 *        reason "tsa_required" (QTS issuance IS the timestamp; MANDATORY).
 *   M2 — issuance + service_type=qes, tsa absent → signature_valid:true,
 *        tsa_state "tsa_recommended" (advisory).
 *   M3 — revocation, tsa absent → signature_valid:true,
 *        tsa_state "tsa_recommended" (advisory).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { mintIssuance, mintRevocation } from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseCommon, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

const baseIssuance = {
  service_policy_oid: "0.4.0.1862.1.1",
  service_recipient_commit: "sha256:" + "b".repeat(64),
  artefact_hash: "sha256:" + "a".repeat(64),
  artefact_metadata_commit: "sha256:" + "c".repeat(64),
  signature_format: "pades_b_lta" as const,
  qcert_serial_commit: "sha256:" + "9".repeat(64),
  tsl_country: "ES",
  tsl_entry_hash: "sha256:" + "d".repeat(64),
  tsl_signed_tree_head_root: "sha256:" + "f".repeat(64),
  tsl_tree_size: 42,
  tsl_inclusion_proof: [],
  tsl_log_time: "2026-05-16T10:00:00Z",
};

// ── M1: qts issuance without tsa hard-fails (MANDATORY) ───────────────────────

test("M1: issuance+qts without tsa → signature_valid:false, reason tsa_required", async () => {
  const env = await mintIssuance({
    ...baseCommon,
    profile: "eidas.qts" as const,
    signingKey: makeSigningKey(),
    ...baseIssuance,
    service_type: "qts" as const,
  });
  assert.equal(env.tsa, null, "fixture: tsa must be absent");

  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false, "qts issuance without TSA must hard-fail");
  assert.equal(r.reason, "tsa_required");
});

// ── M2: qes issuance without tsa → advisory tsa_recommended ───────────────────

test("M2: issuance+qes without tsa → signature_valid:true, tsa_state tsa_recommended", async () => {
  const env = await mintIssuance({
    ...baseCommon,
    signingKey: makeSigningKey(),
    ...baseIssuance,
    service_type: "qes" as const,
  });
  assert.equal(env.tsa, null, "fixture: tsa must be absent");

  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal(r.tsa_state, "tsa_recommended");
  assert.equal(r.reason, undefined);
});

// ── M3: revocation without tsa → advisory tsa_recommended ─────────────────────

test("M3: revocation without tsa → signature_valid:true, tsa_state tsa_recommended", async () => {
  const env = await mintRevocation({
    ...baseCommon,
    signingKey: makeSigningKey(),
    prev: "01HISSUANCE00000000000000",
    reason: "tsl_delisted",
    tsl_country: "DE",
    tsl_entry_hash: "sha256:" + "d".repeat(64),
    tsl_signed_tree_head_root: "sha256:" + "f".repeat(64),
    tsl_tree_size: 10,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-16T14:00:00Z",
  });
  assert.equal(env.tsa, null, "fixture: tsa must be absent");

  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal(r.tsa_state, "tsa_recommended");
});
