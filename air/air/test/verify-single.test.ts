/**
 * Tests for the per-event-type AIR body verifier (spec §3.1 + §4 +
 * D10-AIR-1).
 *
 * Coverage: one happy path per event_type (11 variants) plus the rejection
 * cases named explicitly in §4.1–§4.9, the consultation_output_empty
 * HARD-invalid (§4.4), the dpa_jurisdiction format check (§4.7), and the
 * cross-event pinning regression (one pinned field flipped to a non-null
 * value per event surfaces the corresponding `<field>.must_be_null` error).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAirBody, isAirProfile } from "../src/verify-single.ts";
import {
  EMPTY_DOC_HASH_PREFIXED,
  completed,
  dpoAdvised,
  priorConsultationInitiated,
  priorConsultationResolved,
  processingAuthorised,
  processingBlocked,
  reviewed,
  scopeLocked,
  stakeholdersConsulted,
  terminated,
  thresholdTriggered,
} from "./_helpers/bodies.ts";

// ── Happy paths (one per event type) ─────────────────────────────────────────

test("verify-single: dpia.threshold_triggered happy path", () => {
  const r = verifyAirBody(thresholdTriggered());
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.notEqual(r.body, null);
});

test("verify-single: dpia.scope_locked happy path", () => {
  const r = verifyAirBody(scopeLocked());
  assert.equal(r.valid, true);
});

test("verify-single: dpia.dpo_advised happy path", () => {
  const r = verifyAirBody(dpoAdvised());
  assert.equal(r.valid, true);
});

test("verify-single: dpia.stakeholders_consulted happy path", () => {
  const r = verifyAirBody(stakeholdersConsulted());
  assert.equal(r.valid, true);
});

test("verify-single: dpia.completed happy path (medium risk, no composition)", () => {
  const r = verifyAirBody(completed());
  assert.equal(r.valid, true);
});

test("verify-single: dpia.completed accepts composition arrays", () => {
  const r = verifyAirBody(
    completed({
      aer_receipt_ids: ["aer-1", "aer-2"],
      alr_receipt_ids: ["alr-1"],
    }),
  );
  assert.equal(r.valid, true);
});

test("verify-single: dpia.reviewed happy path", () => {
  const r = verifyAirBody(reviewed());
  assert.equal(r.valid, true);
});

test("verify-single: dpia.reviewed accepts abr_receipt_id when breach-triggered", () => {
  const r = verifyAirBody(
    reviewed({ review_outcome: "material_change", abr_receipt_id: "abr-1" }),
  );
  assert.equal(r.valid, true);
});

test("verify-single: dpia.prior_consultation_initiated happy path (alpha-2)", () => {
  const r = verifyAirBody(priorConsultationInitiated());
  assert.equal(r.valid, true);
});

test("verify-single: dpia.prior_consultation_initiated accepts EU-EDPB", () => {
  const r = verifyAirBody(priorConsultationInitiated({ dpa_jurisdiction: "EU-EDPB" }));
  assert.equal(r.valid, true);
});

test("verify-single: dpia.prior_consultation_resolved happy path", () => {
  const r = verifyAirBody(priorConsultationResolved());
  assert.equal(r.valid, true);
});

test("verify-single: dpia.prior_consultation_resolved accepts dpa_did when present", () => {
  const r = verifyAirBody(priorConsultationResolved({ dpa_did: "did:web:aepd.es" }));
  assert.equal(r.valid, true);
});

test("verify-single: dpia.processing_authorised happy path", () => {
  const r = verifyAirBody(processingAuthorised());
  assert.equal(r.valid, true);
});

test("verify-single: dpia.processing_blocked happy path", () => {
  const r = verifyAirBody(processingBlocked());
  assert.equal(r.valid, true);
});

test("verify-single: dpia.terminated happy path", () => {
  const r = verifyAirBody(terminated());
  assert.equal(r.valid, true);
});

// ── Top-level shape rejections ────────────────────────────────────────────────

test("verify-single: non-object body rejected", () => {
  const r = verifyAirBody("not-a-body");
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["body.not_object"]);
});

test("verify-single: null body rejected", () => {
  const r = verifyAirBody(null);
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["body.not_object"]);
});

test("verify-single: unknown event_type rejected", () => {
  const b = { ...thresholdTriggered(), event_type: "dpia.bogus" };
  const r = verifyAirBody(b);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("event_type.unknown"));
});

test("verify-single: missing air_receipt_id rejected", () => {
  const { air_receipt_id: _drop, ...rest } = thresholdTriggered();
  const r = verifyAirBody(rest);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("air_receipt_id.required"));
});

test("verify-single: missing processing_activity_id rejected", () => {
  const { processing_activity_id: _drop, ...rest } = thresholdTriggered();
  const r = verifyAirBody(rest);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("processing_activity_id.required"));
});

// ── §4.1 dpia.threshold_triggered rejections ─────────────────────────────────

test("verify-single: threshold_triggered missing processing_activity_hash", () => {
  const r = verifyAirBody({ ...thresholdTriggered(), processing_activity_hash: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("processing_activity_hash.required"));
});

test("verify-single: threshold_triggered invalid processing_start_at", () => {
  const r = verifyAirBody({ ...thresholdTriggered(), processing_start_at: "not-a-date" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("processing_start_at.invalid"));
});

test("verify-single: threshold_triggered with unintended scope_hash fires pin error", () => {
  const r = verifyAirBody({ ...thresholdTriggered(), scope_hash: "sha256:bogus" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("scope_hash.must_be_null"));
});

// ── §4.2 dpia.scope_locked rejections ─────────────────────────────────────────

test("verify-single: scope_locked missing scope_hash", () => {
  const r = verifyAirBody({ ...scopeLocked(), scope_hash: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("scope_hash.required"));
});

test("verify-single: scope_locked rejects bleed-through processing_activity_hash", () => {
  const r = verifyAirBody({
    ...scopeLocked(),
    processing_activity_hash: "sha256:bleed",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("processing_activity_hash.must_be_null"));
});

// ── §4.3 dpia.dpo_advised rejections ─────────────────────────────────────────

test("verify-single: dpo_advised missing dpo_did_or_email_commit", () => {
  const r = verifyAirBody({ ...dpoAdvised(), dpo_did_or_email_commit: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpo_did_or_email_commit.required"));
});

test("verify-single: dpo_advised missing dpo_advice_hash", () => {
  const r = verifyAirBody({ ...dpoAdvised(), dpo_advice_hash: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpo_advice_hash.required"));
});

// ── §4.4 dpia.stakeholders_consulted rejections (incl. HARD empty-doc) ───────

test("verify-single: stakeholders_consulted rejects unknown consultation_method", () => {
  const r = verifyAirBody({
    ...stakeholdersConsulted(),
    consultation_method: "espionage",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("consultation_method.invalid"));
});

test("verify-single: stakeholders_consulted missing consultation_output_hash", () => {
  const r = verifyAirBody({ ...stakeholdersConsulted(), consultation_output_hash: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("consultation_output_hash.required"));
});

test("verify-single: stakeholders_consulted HARD rejects sha256(empty) — prefixed", () => {
  const r = verifyAirBody({
    ...stakeholdersConsulted(),
    consultation_output_hash: EMPTY_DOC_HASH_PREFIXED,
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("consultation_output_empty"));
});

test("verify-single: stakeholders_consulted HARD rejects sha256(empty) — bare hex", () => {
  const r = verifyAirBody({
    ...stakeholdersConsulted(),
    consultation_output_hash:
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("consultation_output_empty"));
});

test("verify-single: stakeholders_consulted accepts representative_org method", () => {
  const r = verifyAirBody(stakeholdersConsulted({ consultation_method: "representative_org" }));
  assert.equal(r.valid, true);
});

// ── §4.5 dpia.completed rejections ────────────────────────────────────────────

test("verify-single: completed missing dpia_artifact_hash", () => {
  const r = verifyAirBody({ ...completed(), dpia_artifact_hash: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpia_artifact_hash.required"));
});

test("verify-single: completed missing dpia_uri", () => {
  const r = verifyAirBody({ ...completed(), dpia_uri: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpia_uri.required"));
});

test("verify-single: completed rejects unknown residual_risk_level", () => {
  const r = verifyAirBody({ ...completed(), residual_risk_level: "catastrophic" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("residual_risk_level.invalid"));
});

test("verify-single: completed rejects malformed review_due_at", () => {
  const r = verifyAirBody({ ...completed(), review_due_at: "tomorrow" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("review_due_at.invalid"));
});

test("verify-single: completed rejects empty aer_receipt_ids array", () => {
  const r = verifyAirBody({ ...completed(), aer_receipt_ids: [] });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("aer_receipt_ids.invalid"));
});

test("verify-single: completed accepts all four composition arrays", () => {
  const r = verifyAirBody(
    completed({
      aer_receipt_ids: ["aer-1"],
      atr_receipt_ids: ["atr-1"],
      alr_receipt_ids: ["alr-1"],
      apur_receipt_ids: ["apur-1"],
    }),
  );
  assert.equal(r.valid, true);
});

// ── §4.6 dpia.reviewed rejections ─────────────────────────────────────────────

test("verify-single: reviewed rejects unknown review_outcome", () => {
  const r = verifyAirBody({ ...reviewed(), review_outcome: "in_progress" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("review_outcome.invalid"));
});

test("verify-single: reviewed missing review_evidence_hash", () => {
  const r = verifyAirBody({ ...reviewed(), review_evidence_hash: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("review_evidence_hash.required"));
});

test("verify-single: reviewed rejects empty-string abr_receipt_id", () => {
  const r = verifyAirBody({ ...reviewed(), abr_receipt_id: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("abr_receipt_id.invalid"));
});

// ── §4.7 dpia.prior_consultation_initiated rejections ────────────────────────

test("verify-single: prior_consultation_initiated rejects lowercase jurisdiction", () => {
  const r = verifyAirBody({ ...priorConsultationInitiated(), dpa_jurisdiction: "es" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpa_jurisdiction.invalid"));
});

test("verify-single: prior_consultation_initiated rejects three-letter jurisdiction", () => {
  const r = verifyAirBody({ ...priorConsultationInitiated(), dpa_jurisdiction: "ESP" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpa_jurisdiction.invalid"));
});

test("verify-single: prior_consultation_initiated rejects empty submission_hash", () => {
  const r = verifyAirBody({ ...priorConsultationInitiated(), submission_hash: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("submission_hash.required"));
});

// ── §4.8 dpia.prior_consultation_resolved rejections ─────────────────────────

test("verify-single: prior_consultation_resolved missing dpa_advice_hash", () => {
  const r = verifyAirBody({ ...priorConsultationResolved(), dpa_advice_hash: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpa_advice_hash.required"));
});

test("verify-single: prior_consultation_resolved missing controller_response_hash", () => {
  const r = verifyAirBody({ ...priorConsultationResolved(), controller_response_hash: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("controller_response_hash.required"));
});

test("verify-single: prior_consultation_resolved rejects empty-string dpa_did", () => {
  const r = verifyAirBody({ ...priorConsultationResolved(), dpa_did: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpa_did.invalid"));
});

// ── §4.9 terminal trio rejections ─────────────────────────────────────────────

test("verify-single: processing_authorised wrong terminal_disposition rejected", () => {
  const r = verifyAirBody({ ...processingAuthorised(), terminal_disposition: "blocked" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("terminal_disposition.must_be_authorised"));
});

test("verify-single: processing_blocked wrong terminal_disposition rejected", () => {
  const r = verifyAirBody({ ...processingBlocked(), terminal_disposition: "authorised" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("terminal_disposition.must_be_blocked"));
});

test("verify-single: terminated wrong terminal_disposition rejected", () => {
  const r = verifyAirBody({ ...terminated(), terminal_disposition: "authorised" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("terminal_disposition.must_be_terminated"));
});

test("verify-single: terminated missing termination_reason_hash", () => {
  const r = verifyAirBody({ ...terminated(), termination_reason_hash: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("termination_reason_hash.required"));
});

// ── Cross-event pinning regression sweep (1 per event) ───────────────────────

test("verify-single: pin sweep — completed.dpa_advice_hash bleed rejected", () => {
  const r = verifyAirBody({ ...completed(), dpa_advice_hash: "sha256:bleed" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpa_advice_hash.must_be_null"));
});

test("verify-single: pin sweep — reviewed.dpia_artifact_hash bleed rejected", () => {
  const r = verifyAirBody({ ...reviewed(), dpia_artifact_hash: "sha256:bleed" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpia_artifact_hash.must_be_null"));
});

test("verify-single: pin sweep — prior_consultation_initiated.scope_hash bleed rejected", () => {
  const r = verifyAirBody({
    ...priorConsultationInitiated(),
    scope_hash: "sha256:bleed",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("scope_hash.must_be_null"));
});

test("verify-single: pin sweep — prior_consultation_resolved.dpa_jurisdiction bleed rejected", () => {
  const r = verifyAirBody({
    ...priorConsultationResolved(),
    dpa_jurisdiction: "ES",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpa_jurisdiction.must_be_null"));
});

test("verify-single: pin sweep — processing_authorised.termination_reason_hash bleed rejected", () => {
  const r = verifyAirBody({
    ...processingAuthorised(),
    termination_reason_hash: "sha256:bleed",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("termination_reason_hash.must_be_null"));
});

test("verify-single: pin sweep — processing_blocked.review_outcome bleed rejected", () => {
  const r = verifyAirBody({
    ...processingBlocked(),
    review_outcome: "material_change",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("review_outcome.must_be_null"));
});

test("verify-single: pin sweep — terminated.aer_receipt_ids bleed rejected", () => {
  const r = verifyAirBody({
    ...terminated(),
    aer_receipt_ids: ["aer-1"],
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("aer_receipt_ids.must_be_null"));
});

test("verify-single: pin sweep — dpo_advised.consultation_method bleed rejected", () => {
  const r = verifyAirBody({
    ...dpoAdvised(),
    consultation_method: "survey",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("consultation_method.must_be_null"));
});

test("verify-single: pin sweep — stakeholders_consulted.dpo_advice_hash bleed rejected", () => {
  const r = verifyAirBody({
    ...stakeholdersConsulted(),
    dpo_advice_hash: "sha256:bleed",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("dpo_advice_hash.must_be_null"));
});

// ── Exported profile predicate ───────────────────────────────────────────────

test("isAirProfile: accepts the 5 v1 profiles", () => {
  assert.equal(isAirProfile("impact.art35_3_a_automated_decisions"), true);
  assert.equal(isAirProfile("impact.art35_3_b_large_scale_special_categories"), true);
  assert.equal(isAirProfile("impact.art35_3_c_public_monitoring"), true);
  assert.equal(isAirProfile("impact.art35_4_dpa_list"), true);
  assert.equal(isAirProfile("impact.voluntary"), true);
});

test("isAirProfile: rejects unknown profile strings", () => {
  assert.equal(isAirProfile("impact.bogus"), false);
  assert.equal(isAirProfile("breach.gdpr.art33"), false);
  assert.equal(isAirProfile(""), false);
  assert.equal(isAirProfile(null), false);
  assert.equal(isAirProfile(undefined), false);
});
