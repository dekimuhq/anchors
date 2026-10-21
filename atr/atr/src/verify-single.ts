/**
 * Per-event-type ATR body verifier (spec §4).
 *
 * Validates the discriminated union on `body.event_type` and per-event
 * required-field rules. Called by the factory's body-validation step; also
 * exported for callers that hold a body in hand.
 *
 * §C scope: event_type dispatch + per-event field rules. Profile-specific
 * validation lives in `@dekimuhq/atr-profiles`; this module only confirms
 * base structural shape.
 */

import type {
  AtrBody,
  AtrAssessmentOutcome,
  AtrSubjectCountBucket,
  AtrSuspensionTrigger,
} from "./types.ts";

// ── Public surface ────────────────────────────────────────────────────────────

export interface VerifyBodyResult {
  /** True iff every structural check in §4 passes. */
  valid: boolean;
  /** Stable, machine-readable failure codes. Empty when `valid === true`. */
  errors: string[];
  /** Narrowed body when valid; null otherwise. */
  body: AtrBody | null;
}

/**
 * Validate an ATR `body` against spec §4 per-event-type rules.
 * Returns the narrowed discriminated-union body on success.
 */
export function verifyAtrBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  // ── Event-type dispatch ────────────────────────────────────────────────────
  switch (b.event_type) {
    case "arrangement":
      validateArrangement(b, errors);
      break;
    case "transfer":
      validateTransfer(b, errors);
      break;
    case "tia":
      validateTia(b, errors);
      break;
    case "suspension":
      validateSuspension(b, errors);
      break;
    default:
      errors.push("event_type.unknown");
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AtrBody };
}

// ── §4.1 arrangement ─────────────────────────────────────────────────────────

function validateArrangement(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.arrangement_id_commit)) errors.push("arrangement_id_commit.missing");
  if (!isNonEmptyString(b.recipient_commit)) errors.push("recipient_commit.missing");
  if (!isNonEmptyString(b.destination_country)) errors.push("destination_country.missing");
  if (!isNonEmptyString(b.mechanism_version)) errors.push("mechanism_version.missing");
  if (!isNonEmptyString(b.contract_doc_hash)) errors.push("contract_doc_hash.missing");
  if (!isNonEmptyString(b.in_force_from)) errors.push("in_force_from.missing");
  if (!isNonEmptyString(b.supplementary_measures_hash)) errors.push("supplementary_measures_hash.missing");
  // in_force_until is nullable — no validation required when null
  if (b.in_force_until !== null && b.in_force_until !== undefined && typeof b.in_force_until !== "string") {
    errors.push("in_force_until.invalid");
  }
}

// ── §4.2 transfer ────────────────────────────────────────────────────────────

function validateTransfer(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.arrangement_hash)) errors.push("arrangement_hash.missing");
  if (!isNonEmptyString(b.destination_country)) errors.push("destination_country.missing");
  if (!isNonEmptyString(b.recipient_commit)) errors.push("recipient_commit.missing");
  if (!isNonEmptyStringArray(b.data_categories)) errors.push("data_categories.missing");
  if (!isSubjectCountBucket(b.subject_count_bucket)) errors.push("subject_count_bucket.invalid");
  if (!isNonEmptyString(b.transfer_window_start)) errors.push("transfer_window_start.missing");
  if (!isNonEmptyString(b.transfer_window_end)) errors.push("transfer_window_end.missing");
  // nullable cross-ref fields: tia_hash, artifact_apr_hash, consent_receipt_hash,
  //   purpose_binding_hash, qts_attestation_hash — presence accepted, not required
}

// ── §4.3 tia ─────────────────────────────────────────────────────────────────

function validateTia(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.arrangement_hash)) errors.push("arrangement_hash.missing");
  if (!isNonEmptyString(b.destination_country)) errors.push("destination_country.missing");
  if (!isNonEmptyString(b.assessment_doc_hash)) errors.push("assessment_doc_hash.missing");
  if (!isNonEmptyString(b.supplementary_measures_hash)) errors.push("supplementary_measures_hash.missing");
  if (!isNonEmptyStringArray(b.surveillance_law_refs)) errors.push("surveillance_law_refs.missing");
  if (!isAssessmentOutcome(b.assessment_outcome)) errors.push("assessment_outcome.invalid");
  if (!isNonEmptyString(b.valid_from)) errors.push("valid_from.missing");
  if (!isNonEmptyString(b.valid_until)) errors.push("valid_until.missing");
}

// ── §4.4 suspension ───────────────────────────────────────────────────────────

function validateSuspension(b: Record<string, unknown>, errors: string[]): void {
  if (!isSuspensionTrigger(b.trigger)) errors.push("trigger.invalid");
  if (!isNonEmptyString(b.trigger_ref_hash)) errors.push("trigger_ref_hash.missing");
  if (!isNonEmptyString(b.effective_at)) errors.push("effective_at.missing");
}

// ── Shape predicates ──────────────────────────────────────────────────────────

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function isNonEmptyStringArray(v: unknown): v is readonly string[] {
  return (
    Array.isArray(v) &&
    v.length > 0 &&
    (v as unknown[]).every((item) => typeof item === "string")
  );
}

const SUBJECT_COUNT_BUCKETS = new Set<string>([
  "1",
  "2_9",
  "10_99",
  "100_999",
  "1k_9k",
  "10k_99k",
  "100k_plus",
]);

function isSubjectCountBucket(v: unknown): v is AtrSubjectCountBucket {
  return typeof v === "string" && SUBJECT_COUNT_BUCKETS.has(v);
}

const ASSESSMENT_OUTCOMES = new Set<string>([
  "permitted_plain",
  "permitted_with_supplementary",
  "not_permitted",
]);

function isAssessmentOutcome(v: unknown): v is AtrAssessmentOutcome {
  return typeof v === "string" && ASSESSMENT_OUTCOMES.has(v);
}

const SUSPENSION_TRIGGERS = new Set<string>([
  "cjeu_judgment",
  "dpa_order",
  "adequacy_repeal",
  "controller_decision",
  "dpf_delisting",
  "arrangement_expiry",
]);

function isSuspensionTrigger(v: unknown): v is AtrSuspensionTrigger {
  return typeof v === "string" && SUSPENSION_TRIGGERS.has(v);
}

// Re-export body variant types for callers narrowing on event_type.
export type {
  AtrArrangementBody,
  AtrTransferBody,
  AtrTiaBody,
  AtrSuspensionBody,
} from "./types.ts";
