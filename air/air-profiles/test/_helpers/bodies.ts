/**
 * Test-only body builders for the eleven AIR event variants.
 *
 * Each builder returns a minimal valid body for the named event type, ready
 * to be type-narrowed by `verifyAirBody`. Overrides let individual tests
 * vary one field while keeping the rest of the body well-formed.
 *
 * These helpers are intentionally NOT exported from the package; they live
 * in `test/_helpers/` so the production surface stays unchanged.
 */

import type { AirBody } from "../../src/body.ts";

const SHA = "sha256:" + "a".repeat(64);

/** Common base every event variant carries (D10-AIR-2 + D10-AIR-3). */
export const BASE_AIR = {
  air_receipt_id: "01J0AIRTESTRECEIPT0000000000",
  processing_activity_id: "pa:test-001",
  qts_attestation_hash: null,
} as const;

export function thresholdTriggeredBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.threshold_triggered" }>> = {},
): Extract<AirBody, { event_type: "dpia.threshold_triggered" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.threshold_triggered",
    processing_activity_hash: SHA,
    processing_start_at: "2026-01-01T00:00:00Z",
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...over,
  };
}

export function scopeLockedBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.scope_locked" }>> = {},
): Extract<AirBody, { event_type: "dpia.scope_locked" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.scope_locked",
    scope_hash: SHA,
    processing_activity_hash: null,
    processing_start_at: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...over,
  };
}

export function dpoAdvisedBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.dpo_advised" }>> = {},
): Extract<AirBody, { event_type: "dpia.dpo_advised" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.dpo_advised",
    dpo_did_or_email_commit: SHA,
    dpo_advice_hash: SHA,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...over,
  };
}

export function stakeholdersConsultedBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.stakeholders_consulted" }>> = {},
): Extract<AirBody, { event_type: "dpia.stakeholders_consulted" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.stakeholders_consulted",
    consultation_method: "survey",
    consultation_output_hash: SHA,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...over,
  };
}

export function completedBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.completed" }>> = {},
): Extract<AirBody, { event_type: "dpia.completed" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.completed",
    dpia_artifact_hash: SHA,
    dpia_uri: "https://controller.example/dpia.pdf",
    residual_risk_level: "medium",
    review_due_at: "2027-01-01T00:00:00Z",
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    abr_receipt_id: null,
    ...over,
  };
}

export function reviewedBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.reviewed" }>> = {},
): Extract<AirBody, { event_type: "dpia.reviewed" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.reviewed",
    review_outcome: "no_material_change",
    review_evidence_hash: SHA,
    abr_receipt_id: null,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    ...over,
  };
}

export function priorConsultationInitiatedBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.prior_consultation_initiated" }>> = {},
): Extract<AirBody, { event_type: "dpia.prior_consultation_initiated" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.prior_consultation_initiated",
    dpa_jurisdiction: "ES",
    submission_hash: SHA,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...over,
  };
}

export function priorConsultationResolvedBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.prior_consultation_resolved" }>> = {},
): Extract<AirBody, { event_type: "dpia.prior_consultation_resolved" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.prior_consultation_resolved",
    dpa_advice_hash: SHA,
    controller_response_hash: SHA,
    dpa_did: null,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...over,
  };
}

export function processingAuthorisedBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.processing_authorised" }>> = {},
): Extract<AirBody, { event_type: "dpia.processing_authorised" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.processing_authorised",
    terminal_disposition: "authorised",
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...over,
  };
}

export function processingBlockedBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.processing_blocked" }>> = {},
): Extract<AirBody, { event_type: "dpia.processing_blocked" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.processing_blocked",
    terminal_disposition: "blocked",
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...over,
  };
}

export function terminatedBody(
  over: Partial<Extract<AirBody, { event_type: "dpia.terminated" }>> = {},
): Extract<AirBody, { event_type: "dpia.terminated" }> {
  return {
    ...BASE_AIR,
    event_type: "dpia.terminated",
    terminal_disposition: "terminated",
    termination_reason_hash: SHA,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...over,
  };
}

/** Every non-`dpia.completed` body — useful for "validator returns clean" suites. */
export function allNonCompletedBodies(): readonly AirBody[] {
  return [
    thresholdTriggeredBody(),
    scopeLockedBody(),
    dpoAdvisedBody(),
    stakeholdersConsultedBody(),
    reviewedBody(),
    priorConsultationInitiatedBody(),
    priorConsultationResolvedBody(),
    processingAuthorisedBody(),
    processingBlockedBody(),
    terminatedBody(),
  ];
}
