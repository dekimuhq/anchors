/**
 * Tests for the eleven per-event-type convenience wrappers in mint-single.ts.
 * Each wrapper produces a receipt with the correct `event_type` discriminator
 * and `claim_type: "ar.impact.v1"`, and round-trips through verifyReceipt.
 *
 * AIR v1 has NO MANDATORY-TSA event (audit-fix H7) — every minted receipt
 * should verify cleanly without TSA. Three events (`dpia.completed`,
 * `dpia.prior_consultation_initiated`, `dpia.prior_consultation_resolved`)
 * receive a `tsa_recommended` warning per §D mandate matrix; we assert that
 * the warning surfaces but the signature stays valid.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  mintThresholdTriggered,
  mintScopeLocked,
  mintDpoAdvised,
  mintStakeholdersConsulted,
  mintCompleted,
  mintReviewed,
  mintPriorConsultationInitiated,
  mintPriorConsultationResolved,
  mintProcessingAuthorised,
  mintProcessingBlocked,
  mintTerminated,
} from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import type { FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

test("S1: mintThresholdTriggered round-trips through the verifier", async () => {
  const env = await mintThresholdTriggered({
    ...baseCommon,
    signingKey: makeSigningKey(),
    processing_activity_hash: H("a"),
    processing_start_at: "2026-06-01T00:00:00Z",
  });
  assert.equal(env.claim_type, "ar.impact.v1");
  assert.equal((env.body as { event_type: string }).event_type, "dpia.threshold_triggered");
  assert.equal(env.subject, null);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S2: mintScopeLocked round-trips", async () => {
  const env = await mintScopeLocked({
    ...baseCommon,
    signingKey: makeSigningKey(),
    scope_hash: H("b"),
  });
  assert.equal((env.body as { event_type: string }).event_type, "dpia.scope_locked");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S3: mintDpoAdvised round-trips", async () => {
  const env = await mintDpoAdvised({
    ...baseCommon,
    signingKey: makeSigningKey(),
    dpo_did_or_email_commit: H("c"),
    dpo_advice_hash: H("d"),
  });
  assert.equal((env.body as { event_type: string }).event_type, "dpia.dpo_advised");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S4: mintStakeholdersConsulted (survey, no subject) round-trips", async () => {
  const env = await mintStakeholdersConsulted({
    ...baseCommon,
    signingKey: makeSigningKey(),
    consultation_method: "survey",
    consultation_output_hash: H("e"),
  });
  assert.equal((env.body as { event_type: string }).event_type, "dpia.stakeholders_consulted");
  assert.equal(env.subject, null);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S5: mintStakeholdersConsulted (representative_org + sha256 subject) round-trips", async () => {
  const env = await mintStakeholdersConsulted({
    ...baseCommon,
    signingKey: makeSigningKey(),
    consultation_method: "representative_org",
    consultation_output_hash: H("e2"),
    subject: H("f"),
  });
  assert.equal(env.subject, H("f"));
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S6: mintCompleted round-trips with composition fields preserved and tsa_recommended warning surfaces", async () => {
  const env = await mintCompleted({
    ...baseCommon,
    signingKey: makeSigningKey(),
    dpia_artifact_hash: H("g"),
    dpia_uri: "https://controller.example/dpia/x",
    residual_risk_level: "low",
    review_due_at: "2027-05-19T00:00:00Z",
    aer_receipt_ids: ["AER-1"],
    atr_receipt_ids: ["ATR-1"],
    alr_receipt_ids: ["ALR-1"],
    apur_receipt_ids: ["APuR-1"],
  });
  assert.equal((env.body as { event_type: string }).event_type, "dpia.completed");
  const body = env.body as { aer_receipt_ids: readonly string[] };
  assert.deepEqual(body.aer_receipt_ids, ["AER-1"]);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() }) as FamilyVerifyResult;
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal(r.tsa_state, "tsa_recommended");
});

test("S7: mintReviewed round-trips with breach-triggered abr_receipt_id preserved", async () => {
  const env = await mintReviewed({
    ...baseCommon,
    signingKey: makeSigningKey(),
    review_outcome: "material_change",
    review_evidence_hash: H("h"),
    abr_receipt_id: "ABR-2026-0001",
  });
  const body = env.body as { abr_receipt_id: string };
  assert.equal(body.abr_receipt_id, "ABR-2026-0001");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S8: mintPriorConsultationInitiated surfaces tsa_recommended warning, signature valid", async () => {
  const env = await mintPriorConsultationInitiated({
    ...baseCommon,
    signingKey: makeSigningKey(),
    dpa_jurisdiction: "ES",
    submission_hash: H("i"),
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() }) as FamilyVerifyResult;
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal(r.tsa_state, "tsa_recommended");
});

test("S9: mintPriorConsultationResolved surfaces tsa_recommended warning, signature valid", async () => {
  const env = await mintPriorConsultationResolved({
    ...baseCommon,
    signingKey: makeSigningKey(),
    dpa_advice_hash: H("j"),
    controller_response_hash: H("k"),
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() }) as FamilyVerifyResult;
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal(r.tsa_state, "tsa_recommended");
});

test("S10: mintProcessingAuthorised pins terminal_disposition='authorised' and round-trips", async () => {
  const env = await mintProcessingAuthorised({
    ...baseCommon,
    signingKey: makeSigningKey(),
  });
  const body = env.body as { terminal_disposition: string };
  assert.equal(body.terminal_disposition, "authorised");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S11: mintProcessingBlocked pins terminal_disposition='blocked' and round-trips", async () => {
  const env = await mintProcessingBlocked({
    ...baseCommon,
    signingKey: makeSigningKey(),
  });
  const body = env.body as { terminal_disposition: string };
  assert.equal(body.terminal_disposition, "blocked");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S12: mintTerminated pins terminal_disposition='terminated' and round-trips", async () => {
  const env = await mintTerminated({
    ...baseCommon,
    signingKey: makeSigningKey(),
    termination_reason_hash: H("l"),
  });
  const body = env.body as { terminal_disposition: string; termination_reason_hash: string };
  assert.equal(body.terminal_disposition, "terminated");
  assert.equal(body.termination_reason_hash, H("l"));
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S13: subject is null on every non-stakeholders_consulted event", async () => {
  const sk = makeSigningKey();
  const envs = await Promise.all([
    mintThresholdTriggered({ ...baseCommon, signingKey: sk, processing_activity_hash: H("a"), processing_start_at: "2026-06-01T00:00:00Z" }),
    mintScopeLocked({ ...baseCommon, signingKey: sk, scope_hash: H("b") }),
    mintDpoAdvised({ ...baseCommon, signingKey: sk, dpo_did_or_email_commit: H("c"), dpo_advice_hash: H("d") }),
    mintCompleted({ ...baseCommon, signingKey: sk, dpia_artifact_hash: H("g"), dpia_uri: "https://x", residual_risk_level: "low", review_due_at: "2027-05-19T00:00:00Z" }),
    mintReviewed({ ...baseCommon, signingKey: sk, review_outcome: "no_material_change", review_evidence_hash: H("h") }),
    mintPriorConsultationInitiated({ ...baseCommon, signingKey: sk, dpa_jurisdiction: "DE", submission_hash: H("i") }),
    mintPriorConsultationResolved({ ...baseCommon, signingKey: sk, dpa_advice_hash: H("j"), controller_response_hash: H("k") }),
    mintProcessingAuthorised({ ...baseCommon, signingKey: sk }),
    mintProcessingBlocked({ ...baseCommon, signingKey: sk }),
    mintTerminated({ ...baseCommon, signingKey: sk, termination_reason_hash: H("l") }),
  ]);
  for (const e of envs) assert.equal(e.subject, null);
});
