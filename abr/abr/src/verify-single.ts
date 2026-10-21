/**
 * Per-event-type ABR body verifier (spec §3.1 + §4 + D10-ABR-1).
 *
 * Validates the discriminated union on `body.event_type` and the cross-event
 * pinning invariants the discriminated union enforces at the type level
 * (every variant pins all non-applicable fields to `null`). Called by
 * `verifyV2` after envelope-level checks pass; also exported for callers
 * that hold a body in hand.
 *
 * ABR is v=2 only — there is no v=1 body shape. Profile-specific validation
 * (Art. 33 deadline arithmetic, NIS2 phase ordering, DORA scope) lives in
 * `@dekimuhq/abr-profiles`; this module only confirms the active profile
 * string is one of the five spec §5 literals and that base shape is correct.
 *
 * §C scope: per-event required-field assertions + pinned-null assertions +
 * the Art. 34(3)(c) public-communication requirement (spec §4.6). §D, §E,
 * §G enforce TSA-mandate / subject-presence / composition; those checks
 * ride on envelope state and live in their own modules.
 */

import type {
  AbrBody,
  AbrExemptionGround,
  AbrNotificationPhase,
  AbrProfile,
  AbrSeverityClass,
} from "./types.ts";

// ── Public surface ────────────────────────────────────────────────────────────

export interface VerifyBodyResult {
  /** True iff every structural check in §3.1 + §4 passes. */
  valid: boolean;
  /** Stable, machine-readable failure codes. Empty when `valid === true`. */
  errors: string[];
  /** Narrowed body when valid; null otherwise. */
  body: AbrBody | null;
}

/**
 * Validate an ABR `body` against spec §3.1 (shared fields) and §4 (per-event
 * rules). Returns the narrowed discriminated-union body on success.
 */
export function verifyAbrBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  // ── Base fields shared by every event type (D10-ABR-3) ─────────────────────
  if (!isAbrProfile(b.profile)) errors.push("profile.unregistered");
  if (!isNonEmptyString(b.incident_correlation_id)) {
    errors.push("incident_correlation_id.required");
  }

  // ── Event-type dispatch (D10-ABR-1) ────────────────────────────────────────
  switch (b.event_type) {
    case "breach.detected":
      validateDetected(b, errors);
      break;
    case "breach.assessed":
      validateAssessed(b, errors);
      break;
    case "breach.dpa_notified":
      validateDpaNotified(b, errors);
      break;
    case "breach.dpa_delayed":
      validateDpaDelayed(b, errors);
      break;
    case "breach.subject_notified":
      validateSubjectNotified(b, errors);
      break;
    case "breach.subject_notification_exempted":
      validateSubjectNotificationExempted(b, errors);
      break;
    case "breach.contained":
      validateContained(b, errors);
      break;
    case "breach.closed":
      validateClosed(b, errors);
      break;
    default:
      errors.push("event_type.unknown");
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AbrBody };
}

// ── §4.1 breach.detected ──────────────────────────────────────────────────────

function validateDetected(b: Record<string, unknown>, errors: string[]): void {
  if (!isIsoTimestamp(b.detected_at)) errors.push("detected_at.invalid");
  if (!isSeverityClass(b.severity_class)) errors.push("severity_class.invalid");
  if (!isNonEmptyStringArray(b.affected_data_categories)) {
    errors.push("affected_data_categories.invalid");
  }
  if (!isNonEmptyString(b.affected_data_hash)) errors.push("affected_data_hash.required");
  if (!isAffectedCount(b.affected_count)) errors.push("affected_count.invalid");
  if (!isNonEmptyString(b.jurisdiction)) errors.push("jurisdiction.required");

  // Composition: optional AER pointer array (§8.4 — audit fix C5).
  if (b.affected_aer_ids !== null && !isNonEmptyStringArray(b.affected_aer_ids)) {
    errors.push("affected_aer_ids.invalid");
  }

  // Cross-event-pinned fields (every non-detected field must be null).
  pinNullMany(
    b,
    [
      "assessment_method_hash",
      "notification_uri",
      "notification_hash",
      "dpa_reference_id",
      "notification_phase",
      "delay_reason_hash",
      "delay_until_at",
      "subject_batch_root",
      "subject_batch_size",
      "exemption_ground",
      "justification_hash",
      "public_communication_uri",
      "containment_at",
      "containment_summary_hash",
      "containment_attestation",
      "closed_at",
      "closure_dpa_reference_id",
      "containment_remediation_arr_ids",
      "transfer_suspension_atr_ids",
      "post_breach_anr_id",
      "qes_aar_id",
    ],
    errors,
  );
}

// ── §4.2 breach.assessed ──────────────────────────────────────────────────────

function validateAssessed(b: Record<string, unknown>, errors: string[]): void {
  if (!isSeverityClass(b.severity_class)) errors.push("severity_class.invalid");
  if (!isNonEmptyString(b.assessment_method_hash)) {
    errors.push("assessment_method_hash.required");
  }
  pinNullMany(
    b,
    [
      "detected_at",
      "affected_data_categories",
      "affected_data_hash",
      "affected_count",
      "jurisdiction",
      "notification_uri",
      "notification_hash",
      "dpa_reference_id",
      "notification_phase",
      "delay_reason_hash",
      "delay_until_at",
      "subject_batch_root",
      "subject_batch_size",
      "exemption_ground",
      "justification_hash",
      "public_communication_uri",
      "containment_at",
      "containment_summary_hash",
      "containment_attestation",
      "closed_at",
      "closure_dpa_reference_id",
      "affected_aer_ids",
      "containment_remediation_arr_ids",
      "transfer_suspension_atr_ids",
      "post_breach_anr_id",
      "qes_aar_id",
    ],
    errors,
  );
}

// ── §4.3 breach.dpa_notified ──────────────────────────────────────────────────

function validateDpaNotified(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.notification_uri)) errors.push("notification_uri.required");
  if (!isNonEmptyString(b.notification_hash)) errors.push("notification_hash.required");
  if (b.dpa_reference_id !== null && !isNonEmptyString(b.dpa_reference_id)) {
    errors.push("dpa_reference_id.invalid");
  }
  if (b.notification_phase !== null && !isNotificationPhase(b.notification_phase)) {
    errors.push("notification_phase.invalid");
  }
  // Profile-side rule: notification_phase is non-null only on NIS2 profile.
  // Surfaced here so callers without the profiles pack still catch the
  // structural drift early.
  if (b.notification_phase !== null && b.profile !== "breach.nis2.art23") {
    errors.push("notification_phase.only_on_nis2");
  }
  if (b.qes_aar_id !== null && !isNonEmptyString(b.qes_aar_id)) {
    errors.push("qes_aar_id.invalid");
  }
  pinNullMany(
    b,
    [
      "detected_at",
      "severity_class",
      "affected_data_categories",
      "affected_data_hash",
      "affected_count",
      "jurisdiction",
      "assessment_method_hash",
      "delay_reason_hash",
      "delay_until_at",
      "subject_batch_root",
      "subject_batch_size",
      "exemption_ground",
      "justification_hash",
      "public_communication_uri",
      "containment_at",
      "containment_summary_hash",
      "containment_attestation",
      "closed_at",
      "closure_dpa_reference_id",
      "affected_aer_ids",
      "containment_remediation_arr_ids",
      "transfer_suspension_atr_ids",
      "post_breach_anr_id",
    ],
    errors,
  );
}

// ── §4.4 breach.dpa_delayed ───────────────────────────────────────────────────

function validateDpaDelayed(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.delay_reason_hash)) errors.push("delay_reason_hash.required");
  if (!isIsoTimestamp(b.delay_until_at)) errors.push("delay_until_at.invalid");
  pinNullMany(
    b,
    [
      "detected_at",
      "severity_class",
      "affected_data_categories",
      "affected_data_hash",
      "affected_count",
      "jurisdiction",
      "assessment_method_hash",
      "notification_uri",
      "notification_hash",
      "dpa_reference_id",
      "notification_phase",
      "subject_batch_root",
      "subject_batch_size",
      "exemption_ground",
      "justification_hash",
      "public_communication_uri",
      "containment_at",
      "containment_summary_hash",
      "containment_attestation",
      "closed_at",
      "closure_dpa_reference_id",
      "affected_aer_ids",
      "containment_remediation_arr_ids",
      "transfer_suspension_atr_ids",
      "post_breach_anr_id",
      "qes_aar_id",
    ],
    errors,
  );
}

// ── §4.5 breach.subject_notified ──────────────────────────────────────────────

function validateSubjectNotified(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.subject_batch_root)) errors.push("subject_batch_root.required");
  if (!isBatchSize(b.subject_batch_size)) errors.push("subject_batch_size.invalid");
  if (!isNonEmptyString(b.notification_uri)) errors.push("notification_uri.required");
  if (!isNonEmptyString(b.notification_hash)) errors.push("notification_hash.required");
  pinNullMany(
    b,
    [
      "detected_at",
      "severity_class",
      "affected_data_categories",
      "affected_data_hash",
      "affected_count",
      "jurisdiction",
      "assessment_method_hash",
      "dpa_reference_id",
      "notification_phase",
      "delay_reason_hash",
      "delay_until_at",
      "exemption_ground",
      "justification_hash",
      "public_communication_uri",
      "containment_at",
      "containment_summary_hash",
      "containment_attestation",
      "closed_at",
      "closure_dpa_reference_id",
      "affected_aer_ids",
      "containment_remediation_arr_ids",
      "transfer_suspension_atr_ids",
      "post_breach_anr_id",
      "qes_aar_id",
    ],
    errors,
  );
}

// ── §4.6 breach.subject_notification_exempted ─────────────────────────────────

function validateSubjectNotificationExempted(
  b: Record<string, unknown>,
  errors: string[],
): void {
  if (!isExemptionGround(b.exemption_ground)) errors.push("exemption_ground.invalid");
  if (!isNonEmptyString(b.justification_hash)) errors.push("justification_hash.required");

  // Art. 34(3)(c) requires a public-communication URL when the exemption
  // ground is "disproportionate effort"; spec §4.6.
  const isDisproportionate = b.exemption_ground === "art34_3_c_disproportionate";
  const hasPublicComm = isNonEmptyString(b.public_communication_uri);
  if (isDisproportionate && !hasPublicComm) {
    errors.push("art34_3_c_public_comm_missing");
  } else if (!isDisproportionate && b.public_communication_uri !== null) {
    errors.push("public_communication_uri.must_be_null");
  } else if (
    isDisproportionate &&
    b.public_communication_uri !== null &&
    !isNonEmptyString(b.public_communication_uri)
  ) {
    errors.push("public_communication_uri.invalid");
  }

  pinNullMany(
    b,
    [
      "detected_at",
      "severity_class",
      "affected_data_categories",
      "affected_data_hash",
      "affected_count",
      "jurisdiction",
      "assessment_method_hash",
      "notification_uri",
      "notification_hash",
      "dpa_reference_id",
      "notification_phase",
      "delay_reason_hash",
      "delay_until_at",
      "subject_batch_root",
      "subject_batch_size",
      "containment_at",
      "containment_summary_hash",
      "containment_attestation",
      "closed_at",
      "closure_dpa_reference_id",
      "affected_aer_ids",
      "containment_remediation_arr_ids",
      "transfer_suspension_atr_ids",
      "post_breach_anr_id",
      "qes_aar_id",
    ],
    errors,
  );
}

// ── §4.7 breach.contained ─────────────────────────────────────────────────────

function validateContained(b: Record<string, unknown>, errors: string[]): void {
  if (!isIsoTimestamp(b.containment_at)) errors.push("containment_at.invalid");
  if (!isNonEmptyString(b.containment_summary_hash)) {
    errors.push("containment_summary_hash.required");
  }

  // Composition fields (audit fix C5, spec §8.1/§8.3).
  if (b.containment_attestation !== null && !isNonEmptyString(b.containment_attestation)) {
    errors.push("containment_attestation.invalid");
  }
  if (
    b.containment_remediation_arr_ids !== null &&
    !isNonEmptyStringArray(b.containment_remediation_arr_ids)
  ) {
    errors.push("containment_remediation_arr_ids.invalid");
  }
  if (
    b.transfer_suspension_atr_ids !== null &&
    !isNonEmptyStringArray(b.transfer_suspension_atr_ids)
  ) {
    errors.push("transfer_suspension_atr_ids.invalid");
  }

  pinNullMany(
    b,
    [
      "detected_at",
      "severity_class",
      "affected_data_categories",
      "affected_data_hash",
      "affected_count",
      "jurisdiction",
      "assessment_method_hash",
      "notification_uri",
      "notification_hash",
      "dpa_reference_id",
      "notification_phase",
      "delay_reason_hash",
      "delay_until_at",
      "subject_batch_root",
      "subject_batch_size",
      "exemption_ground",
      "justification_hash",
      "public_communication_uri",
      "closed_at",
      "closure_dpa_reference_id",
      "affected_aer_ids",
      "post_breach_anr_id",
      "qes_aar_id",
    ],
    errors,
  );
}

// ── §4.8 breach.closed ────────────────────────────────────────────────────────

function validateClosed(b: Record<string, unknown>, errors: string[]): void {
  if (!isIsoTimestamp(b.closed_at)) errors.push("closed_at.invalid");
  if (b.closure_dpa_reference_id !== null && !isNonEmptyString(b.closure_dpa_reference_id)) {
    errors.push("closure_dpa_reference_id.invalid");
  }
  if (b.post_breach_anr_id !== null && !isNonEmptyString(b.post_breach_anr_id)) {
    errors.push("post_breach_anr_id.invalid");
  }
  pinNullMany(
    b,
    [
      "detected_at",
      "severity_class",
      "affected_data_categories",
      "affected_data_hash",
      "affected_count",
      "jurisdiction",
      "assessment_method_hash",
      "notification_uri",
      "notification_hash",
      "dpa_reference_id",
      "notification_phase",
      "delay_reason_hash",
      "delay_until_at",
      "subject_batch_root",
      "subject_batch_size",
      "exemption_ground",
      "justification_hash",
      "public_communication_uri",
      "containment_at",
      "containment_summary_hash",
      "containment_attestation",
      "affected_aer_ids",
      "containment_remediation_arr_ids",
      "transfer_suspension_atr_ids",
      "qes_aar_id",
    ],
    errors,
  );
}

// ── Shape predicates ──────────────────────────────────────────────────────────

const ABR_PROFILES = new Set<string>([
  "breach.gdpr.art33",
  "breach.gdpr.art34",
  "breach.nis2.art23",
  "breach.dora.art19",
  "breach.us_state.attorney_general",
]);

function isAbrProfile(v: unknown): v is AbrProfile {
  return typeof v === "string" && ABR_PROFILES.has(v);
}

const SEVERITY_CLASSES = new Set<string>(["no_risk", "risk", "high_risk"]);

function isSeverityClass(v: unknown): v is AbrSeverityClass {
  return typeof v === "string" && SEVERITY_CLASSES.has(v);
}

const EXEMPTION_GROUNDS = new Set<string>([
  "art34_3_a_encrypted",
  "art34_3_b_mitigated",
  "art34_3_c_disproportionate",
]);

function isExemptionGround(v: unknown): v is AbrExemptionGround {
  return typeof v === "string" && EXEMPTION_GROUNDS.has(v);
}

const NOTIFICATION_PHASES = new Set<string>([
  "early_warning",
  "full_notification",
  "final_report",
]);

function isNotificationPhase(v: unknown): v is AbrNotificationPhase {
  return typeof v === "string" && NOTIFICATION_PHASES.has(v);
}

function isAffectedCount(v: unknown): v is number {
  // -1 is permitted per spec §4.1 (undetermined at receipt time); any other
  // negative is rejected.
  return typeof v === "number" && Number.isInteger(v) && v >= -1;
}

/** Subject batch size: integer in [1, 65 536] per D10-ABR-4 + §4.5. */
function isBatchSize(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 65_536;
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
  AbrAssessedBody,
  AbrClosedBody,
  AbrContainedBody,
  AbrDetectedBody,
  AbrDpaDelayedBody,
  AbrDpaNotifiedBody,
  AbrSubjectNotificationExemptedBody,
  AbrSubjectNotifiedBody,
} from "./types.ts";
