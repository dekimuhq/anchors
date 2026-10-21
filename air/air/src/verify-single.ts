/**
 * Per-event-type AIR body verifier (spec §3.1 + §4 + D10-AIR-1).
 *
 * Validates the discriminated union on `body.event_type` and the cross-event
 * pinning invariants the discriminated union enforces at the type level
 * (every variant pins all non-applicable fields to `null`). Exposed for
 * callers that hold a body in hand. The envelope-v2 dispatch does not call
 * this module — single-receipt body structure is a caller-side concern, in
 * the same pattern as `@dekimuhq/abr`'s `verify-single` module.
 *
 * AIR is v=2 only — there is no v=1 body shape. Profile-specific validation
 * (Art. 35(3)(a) AER linkage, Art. 35(4) DPA-list reference) lives in the
 * separate `@dekimuhq/air-profiles` package; this module only confirms the
 * active profile string is one of the five spec §5 literals and that the
 * base shape is correct.
 *
 * §C scope on the body side:
 *   - shared-field assertions (`air_receipt_id`, `processing_activity_id`,
 *     `profile`);
 *   - per-event required-field assertions per spec §4.1–§4.9;
 *   - cross-event pinned-null assertions (the discriminated union enforces
 *     these at compile time, the verifier catches mis-built bodies at
 *     runtime);
 *   - the `consultation_output_empty` HARD-invalid (spec §4.4): the
 *     `consultation_output_hash` MUST NOT equal the canonical SHA-256 of an
 *     empty document (RFC 6234 / `sha256("")`).
 *
 * §D TSA-mandate checks, §E subject-presence rule, §F profile validators,
 * and §G cross-family composition apply on top of body output in subsequent
 * commits.
 */

import type {
  AirBody,
  AirConsultationMethod,
  AirProfile,
  AirResidualRiskLevel,
  AirReviewOutcome,
} from "./types.ts";

// ── Public surface ────────────────────────────────────────────────────────────

export interface VerifyAirBodyResult {
  /** True iff every structural check in §3.1 + §4 passes. */
  valid: boolean;
  /** Stable, machine-readable failure codes. Empty when `valid === true`. */
  errors: string[];
  /** Narrowed body when valid; null otherwise. */
  body: AirBody | null;
}

/**
 * Validate an AIR `body` against spec §3.1 (shared fields) and §4 (per-event
 * rules). Returns the narrowed discriminated-union body on success.
 */
export function verifyAirBody(body: unknown): VerifyAirBodyResult {
  const errors: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  // ── Base fields shared by every event type (§3.1 + D10-AIR-2 + D10-AIR-3).
  if (!isNonEmptyString(b.air_receipt_id)) {
    errors.push("air_receipt_id.required");
  }
  if (!isNonEmptyString(b.processing_activity_id)) {
    errors.push("processing_activity_id.required");
  }
  // `profile` is part of the envelope-level shape in v1.2 (alongside
  // claim_type / policy_uri); some implementations carry it on body too.
  // The §F profile validators dispatch on envelope.profile; this module
  // does NOT require it to be on the body. No assertion here.

  // ── Event-type dispatch (D10-AIR-1) ────────────────────────────────────────
  switch (b.event_type) {
    case "dpia.threshold_triggered":
      validateThresholdTriggered(b, errors);
      break;
    case "dpia.scope_locked":
      validateScopeLocked(b, errors);
      break;
    case "dpia.dpo_advised":
      validateDpoAdvised(b, errors);
      break;
    case "dpia.stakeholders_consulted":
      validateStakeholdersConsulted(b, errors);
      break;
    case "dpia.completed":
      validateCompleted(b, errors);
      break;
    case "dpia.reviewed":
      validateReviewed(b, errors);
      break;
    case "dpia.prior_consultation_initiated":
      validatePriorConsultationInitiated(b, errors);
      break;
    case "dpia.prior_consultation_resolved":
      validatePriorConsultationResolved(b, errors);
      break;
    case "dpia.processing_authorised":
      validateProcessingAuthorised(b, errors);
      break;
    case "dpia.processing_blocked":
      validateProcessingBlocked(b, errors);
      break;
    case "dpia.terminated":
      validateTerminated(b, errors);
      break;
    default:
      errors.push("event_type.unknown");
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AirBody };
}

// ── §4.1 dpia.threshold_triggered ─────────────────────────────────────────────

function validateThresholdTriggered(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.processing_activity_hash)) {
    errors.push("processing_activity_hash.required");
  }
  if (!isIsoTimestamp(b.processing_start_at)) {
    errors.push("processing_start_at.invalid");
  }
  pinNullMany(b, PINNED_FIELDS_THRESHOLD_TRIGGERED, errors);
}

// ── §4.2 dpia.scope_locked ────────────────────────────────────────────────────

function validateScopeLocked(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.scope_hash)) errors.push("scope_hash.required");
  pinNullMany(b, PINNED_FIELDS_SCOPE_LOCKED, errors);
}

// ── §4.3 dpia.dpo_advised ─────────────────────────────────────────────────────

function validateDpoAdvised(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.dpo_did_or_email_commit)) {
    errors.push("dpo_did_or_email_commit.required");
  }
  if (!isNonEmptyString(b.dpo_advice_hash)) {
    errors.push("dpo_advice_hash.required");
  }
  pinNullMany(b, PINNED_FIELDS_DPO_ADVISED, errors);
}

// ── §4.4 dpia.stakeholders_consulted ──────────────────────────────────────────

function validateStakeholdersConsulted(b: Record<string, unknown>, errors: string[]): void {
  if (!isConsultationMethod(b.consultation_method)) {
    errors.push("consultation_method.invalid");
  }
  if (!isNonEmptyString(b.consultation_output_hash)) {
    errors.push("consultation_output_hash.required");
  } else if (isEmptyDocumentHash(b.consultation_output_hash)) {
    // Spec §4.4 HARD-invalid: hash of an empty document is not a valid
    // consultation record. Canonical empty-doc hash = sha256("") (RFC 6234).
    errors.push("consultation_output_empty");
  }
  pinNullMany(b, PINNED_FIELDS_STAKEHOLDERS_CONSULTED, errors);
}

// ── §4.5 dpia.completed ───────────────────────────────────────────────────────

function validateCompleted(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.dpia_artifact_hash)) {
    errors.push("dpia_artifact_hash.required");
  }
  if (!isNonEmptyString(b.dpia_uri)) errors.push("dpia_uri.required");
  if (!isResidualRiskLevel(b.residual_risk_level)) {
    errors.push("residual_risk_level.invalid");
  }
  if (!isIsoTimestamp(b.review_due_at)) errors.push("review_due_at.invalid");

  // Composition fields (audit fix C5, spec §3.1 / §8).
  if (b.aer_receipt_ids !== null && !isNonEmptyStringArray(b.aer_receipt_ids)) {
    errors.push("aer_receipt_ids.invalid");
  }
  if (b.atr_receipt_ids !== null && !isNonEmptyStringArray(b.atr_receipt_ids)) {
    errors.push("atr_receipt_ids.invalid");
  }
  if (b.alr_receipt_ids !== null && !isNonEmptyStringArray(b.alr_receipt_ids)) {
    errors.push("alr_receipt_ids.invalid");
  }
  if (b.apur_receipt_ids !== null && !isNonEmptyStringArray(b.apur_receipt_ids)) {
    errors.push("apur_receipt_ids.invalid");
  }

  pinNullMany(b, PINNED_FIELDS_COMPLETED, errors);
}

// ── §4.6 dpia.reviewed ────────────────────────────────────────────────────────

function validateReviewed(b: Record<string, unknown>, errors: string[]): void {
  if (!isReviewOutcome(b.review_outcome)) errors.push("review_outcome.invalid");
  if (!isNonEmptyString(b.review_evidence_hash)) {
    errors.push("review_evidence_hash.required");
  }
  if (b.abr_receipt_id !== null && !isNonEmptyString(b.abr_receipt_id)) {
    errors.push("abr_receipt_id.invalid");
  }
  pinNullMany(b, PINNED_FIELDS_REVIEWED, errors);
}

// ── §4.7 dpia.prior_consultation_initiated ────────────────────────────────────

function validatePriorConsultationInitiated(
  b: Record<string, unknown>,
  errors: string[],
): void {
  if (!isDpaJurisdiction(b.dpa_jurisdiction)) {
    errors.push("dpa_jurisdiction.invalid");
  }
  if (!isNonEmptyString(b.submission_hash)) errors.push("submission_hash.required");
  pinNullMany(b, PINNED_FIELDS_PRIOR_CONSULTATION_INITIATED, errors);
}

// ── §4.8 dpia.prior_consultation_resolved ─────────────────────────────────────

function validatePriorConsultationResolved(
  b: Record<string, unknown>,
  errors: string[],
): void {
  if (!isNonEmptyString(b.dpa_advice_hash)) errors.push("dpa_advice_hash.required");
  if (!isNonEmptyString(b.controller_response_hash)) {
    errors.push("controller_response_hash.required");
  }
  if (b.dpa_did !== null && !isNonEmptyString(b.dpa_did)) {
    errors.push("dpa_did.invalid");
  }
  pinNullMany(b, PINNED_FIELDS_PRIOR_CONSULTATION_RESOLVED, errors);
}

// ── §4.9 dpia.processing_authorised (terminal trio member 1) ──────────────────

function validateProcessingAuthorised(b: Record<string, unknown>, errors: string[]): void {
  if (b.terminal_disposition !== "authorised") {
    errors.push("terminal_disposition.must_be_authorised");
  }
  pinNullMany(b, PINNED_FIELDS_PROCESSING_AUTHORISED, errors);
}

// ── §4.9 dpia.processing_blocked (terminal trio member 2) ─────────────────────

function validateProcessingBlocked(b: Record<string, unknown>, errors: string[]): void {
  if (b.terminal_disposition !== "blocked") {
    errors.push("terminal_disposition.must_be_blocked");
  }
  pinNullMany(b, PINNED_FIELDS_PROCESSING_BLOCKED, errors);
}

// ── §4.9 dpia.terminated (terminal trio member 3) ─────────────────────────────

function validateTerminated(b: Record<string, unknown>, errors: string[]): void {
  if (b.terminal_disposition !== "terminated") {
    errors.push("terminal_disposition.must_be_terminated");
  }
  if (!isNonEmptyString(b.termination_reason_hash)) {
    errors.push("termination_reason_hash.required");
  }
  pinNullMany(b, PINNED_FIELDS_TERMINATED, errors);
}

// ── Pin-null field lists per event type ───────────────────────────────────────
//
// Each list enumerates the cross-event fields that MUST be `null` on the
// named event variant. Built from the discriminated-union shape in types.ts.

const PINNED_FIELDS_THRESHOLD_TRIGGERED: readonly string[] = [
  "scope_hash",
  "dpo_did_or_email_commit",
  "dpo_advice_hash",
  "consultation_method",
  "consultation_output_hash",
  "dpia_artifact_hash",
  "dpia_uri",
  "residual_risk_level",
  "review_due_at",
  "review_outcome",
  "review_evidence_hash",
  "dpa_jurisdiction",
  "submission_hash",
  "dpa_advice_hash",
  "dpa_did",
  "controller_response_hash",
  "terminal_disposition",
  "termination_reason_hash",
  "aer_receipt_ids",
  "atr_receipt_ids",
  "alr_receipt_ids",
  "apur_receipt_ids",
  "abr_receipt_id",
];

const PINNED_FIELDS_SCOPE_LOCKED: readonly string[] = [
  "processing_activity_hash",
  "processing_start_at",
  "dpo_did_or_email_commit",
  "dpo_advice_hash",
  "consultation_method",
  "consultation_output_hash",
  "dpia_artifact_hash",
  "dpia_uri",
  "residual_risk_level",
  "review_due_at",
  "review_outcome",
  "review_evidence_hash",
  "dpa_jurisdiction",
  "submission_hash",
  "dpa_advice_hash",
  "dpa_did",
  "controller_response_hash",
  "terminal_disposition",
  "termination_reason_hash",
  "aer_receipt_ids",
  "atr_receipt_ids",
  "alr_receipt_ids",
  "apur_receipt_ids",
  "abr_receipt_id",
];

const PINNED_FIELDS_DPO_ADVISED: readonly string[] = [
  "processing_activity_hash",
  "processing_start_at",
  "scope_hash",
  "consultation_method",
  "consultation_output_hash",
  "dpia_artifact_hash",
  "dpia_uri",
  "residual_risk_level",
  "review_due_at",
  "review_outcome",
  "review_evidence_hash",
  "dpa_jurisdiction",
  "submission_hash",
  "dpa_advice_hash",
  "dpa_did",
  "controller_response_hash",
  "terminal_disposition",
  "termination_reason_hash",
  "aer_receipt_ids",
  "atr_receipt_ids",
  "alr_receipt_ids",
  "apur_receipt_ids",
  "abr_receipt_id",
];

const PINNED_FIELDS_STAKEHOLDERS_CONSULTED: readonly string[] = [
  "processing_activity_hash",
  "processing_start_at",
  "scope_hash",
  "dpo_did_or_email_commit",
  "dpo_advice_hash",
  "dpia_artifact_hash",
  "dpia_uri",
  "residual_risk_level",
  "review_due_at",
  "review_outcome",
  "review_evidence_hash",
  "dpa_jurisdiction",
  "submission_hash",
  "dpa_advice_hash",
  "dpa_did",
  "controller_response_hash",
  "terminal_disposition",
  "termination_reason_hash",
  "aer_receipt_ids",
  "atr_receipt_ids",
  "alr_receipt_ids",
  "apur_receipt_ids",
  "abr_receipt_id",
];

const PINNED_FIELDS_COMPLETED: readonly string[] = [
  "processing_activity_hash",
  "processing_start_at",
  "scope_hash",
  "dpo_did_or_email_commit",
  "dpo_advice_hash",
  "consultation_method",
  "consultation_output_hash",
  "review_outcome",
  "review_evidence_hash",
  "dpa_jurisdiction",
  "submission_hash",
  "dpa_advice_hash",
  "dpa_did",
  "controller_response_hash",
  "terminal_disposition",
  "termination_reason_hash",
  "abr_receipt_id",
];

const PINNED_FIELDS_REVIEWED: readonly string[] = [
  "processing_activity_hash",
  "processing_start_at",
  "scope_hash",
  "dpo_did_or_email_commit",
  "dpo_advice_hash",
  "consultation_method",
  "consultation_output_hash",
  "dpia_artifact_hash",
  "dpia_uri",
  "residual_risk_level",
  "review_due_at",
  "dpa_jurisdiction",
  "submission_hash",
  "dpa_advice_hash",
  "dpa_did",
  "controller_response_hash",
  "terminal_disposition",
  "termination_reason_hash",
  "aer_receipt_ids",
  "atr_receipt_ids",
  "alr_receipt_ids",
  "apur_receipt_ids",
];

const PINNED_FIELDS_PRIOR_CONSULTATION_INITIATED: readonly string[] = [
  "processing_activity_hash",
  "processing_start_at",
  "scope_hash",
  "dpo_did_or_email_commit",
  "dpo_advice_hash",
  "consultation_method",
  "consultation_output_hash",
  "dpia_artifact_hash",
  "dpia_uri",
  "residual_risk_level",
  "review_due_at",
  "review_outcome",
  "review_evidence_hash",
  "dpa_advice_hash",
  "dpa_did",
  "controller_response_hash",
  "terminal_disposition",
  "termination_reason_hash",
  "aer_receipt_ids",
  "atr_receipt_ids",
  "alr_receipt_ids",
  "apur_receipt_ids",
  "abr_receipt_id",
];

const PINNED_FIELDS_PRIOR_CONSULTATION_RESOLVED: readonly string[] = [
  "processing_activity_hash",
  "processing_start_at",
  "scope_hash",
  "dpo_did_or_email_commit",
  "dpo_advice_hash",
  "consultation_method",
  "consultation_output_hash",
  "dpia_artifact_hash",
  "dpia_uri",
  "residual_risk_level",
  "review_due_at",
  "review_outcome",
  "review_evidence_hash",
  "dpa_jurisdiction",
  "submission_hash",
  "terminal_disposition",
  "termination_reason_hash",
  "aer_receipt_ids",
  "atr_receipt_ids",
  "alr_receipt_ids",
  "apur_receipt_ids",
  "abr_receipt_id",
];

const PINNED_FIELDS_PROCESSING_AUTHORISED: readonly string[] = [
  "processing_activity_hash",
  "processing_start_at",
  "scope_hash",
  "dpo_did_or_email_commit",
  "dpo_advice_hash",
  "consultation_method",
  "consultation_output_hash",
  "dpia_artifact_hash",
  "dpia_uri",
  "residual_risk_level",
  "review_due_at",
  "review_outcome",
  "review_evidence_hash",
  "dpa_jurisdiction",
  "submission_hash",
  "dpa_advice_hash",
  "dpa_did",
  "controller_response_hash",
  "termination_reason_hash",
  "aer_receipt_ids",
  "atr_receipt_ids",
  "alr_receipt_ids",
  "apur_receipt_ids",
  "abr_receipt_id",
];

const PINNED_FIELDS_PROCESSING_BLOCKED: readonly string[] = PINNED_FIELDS_PROCESSING_AUTHORISED;

const PINNED_FIELDS_TERMINATED: readonly string[] = [
  "processing_activity_hash",
  "processing_start_at",
  "scope_hash",
  "dpo_did_or_email_commit",
  "dpo_advice_hash",
  "consultation_method",
  "consultation_output_hash",
  "dpia_artifact_hash",
  "dpia_uri",
  "residual_risk_level",
  "review_due_at",
  "review_outcome",
  "review_evidence_hash",
  "dpa_jurisdiction",
  "submission_hash",
  "dpa_advice_hash",
  "dpa_did",
  "controller_response_hash",
  "aer_receipt_ids",
  "atr_receipt_ids",
  "alr_receipt_ids",
  "apur_receipt_ids",
  "abr_receipt_id",
];

// ── Shape predicates ──────────────────────────────────────────────────────────

const AIR_PROFILES = new Set<string>([
  "impact.art35_3_a_automated_decisions",
  "impact.art35_3_b_large_scale_special_categories",
  "impact.art35_3_c_public_monitoring",
  "impact.art35_4_dpa_list",
  "impact.voluntary",
]);

/**
 * Exported for callers (e.g. air-profiles validators) that want to confirm
 * a profile string is one of the v1 set without importing the full body
 * verifier.
 */
export function isAirProfile(v: unknown): v is AirProfile {
  return typeof v === "string" && AIR_PROFILES.has(v);
}

const RESIDUAL_RISK_LEVELS = new Set<string>(["low", "medium", "high"]);

function isResidualRiskLevel(v: unknown): v is AirResidualRiskLevel {
  return typeof v === "string" && RESIDUAL_RISK_LEVELS.has(v);
}

const CONSULTATION_METHODS = new Set<string>([
  "survey",
  "focus_group",
  "representative_org",
  "public_consultation",
  "ngo_review",
  "internal_advisory_panel",
  "other",
]);

function isConsultationMethod(v: unknown): v is AirConsultationMethod {
  return typeof v === "string" && CONSULTATION_METHODS.has(v);
}

const REVIEW_OUTCOMES = new Set<string>([
  "no_material_change",
  "material_change",
  "superseded",
]);

function isReviewOutcome(v: unknown): v is AirReviewOutcome {
  return typeof v === "string" && REVIEW_OUTCOMES.has(v);
}

/**
 * `dpa_jurisdiction` per spec §4.7: ISO 3166-1 alpha-2 (regex `/^[A-Z]{2}$/`)
 * or the literal `"EU-EDPB"` for EDPB consistency-mechanism cases.
 */
function isDpaJurisdiction(v: unknown): v is string {
  if (typeof v !== "string") return false;
  if (v === "EU-EDPB") return true;
  return /^[A-Z]{2}$/.test(v);
}

function isNonEmptyStringArray(v: unknown): v is readonly string[] {
  if (!Array.isArray(v)) return false;
  if (v.length === 0) return false;
  for (const item of v) {
    if (typeof item !== "string" || item.length === 0) return false;
  }
  return true;
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function isIsoTimestamp(v: unknown): boolean {
  if (typeof v !== "string") return false;
  const ms = Date.parse(v);
  return !Number.isNaN(ms);
}

/**
 * SHA-256 of the empty string, in the two surface forms the family permits
 * (`sha256:<hex>` prefixed and bare-hex). Either equals `consultation_output_empty`.
 *
 * Hex value: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
 */
const EMPTY_DOC_HASH_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const EMPTY_DOC_HASH_PREFIXED = `sha256:${EMPTY_DOC_HASH_HEX}`;

function isEmptyDocumentHash(v: unknown): boolean {
  if (typeof v !== "string") return false;
  return v === EMPTY_DOC_HASH_HEX || v === EMPTY_DOC_HASH_PREFIXED;
}

function pinNullMany(
  b: Record<string, unknown>,
  fields: readonly string[],
  errors: string[],
): void {
  for (const f of fields) {
    if (b[f] !== null) errors.push(`${f}.must_be_null`);
  }
}

// Re-export the variant interfaces so callers narrowing on event_type get the
// per-variant shape without reaching into ./types.ts.
export type {
  AirCompletedBody,
  AirDpoAdvisedBody,
  AirPriorConsultationInitiatedBody,
  AirPriorConsultationResolvedBody,
  AirProcessingAuthorisedBody,
  AirProcessingBlockedBody,
  AirReviewedBody,
  AirScopeLockedBody,
  AirStakeholdersConsultedBody,
  AirTerminatedBody,
  AirThresholdTriggeredBody,
} from "./types.ts";
