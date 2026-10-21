/**
 * Per-event-type APuR body verifier (spec §4).
 *
 * Validates the discriminated union on `body.event_type` and per-event
 * required-field rules. Called by the factory's body-validation step; also
 * exported for callers that hold a body in hand.
 *
 * §C scope: event_type dispatch + structural field checks per §4.1–§4.3.
 * Profile-specific validation lives in `@dekimuhq/apur-profiles`; this module
 * only confirms base structural shape.
 */

import type { ApurBody } from "./types.ts";

// ── Public surface ────────────────────────────────────────────────────────────

export interface VerifyBodyResult {
  /** True iff every structural check in §4 passes. */
  valid: boolean;
  /** Stable, machine-readable failure codes. Empty when `valid === true`. */
  errors: string[];
  /** Narrowed body when valid; null otherwise. */
  body: ApurBody | null;
}

/**
 * Validate an APuR `body` against spec §4 per-event-type rules.
 * Returns the narrowed discriminated-union body on success.
 */
export function verifyApurBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  // ── Event-type dispatch ────────────────────────────────────────────────────
  switch (b.event_type) {
    case "binding":
      validateBinding(b, errors);
      break;
    case "repurpose":
      validateRepurpose(b, errors);
      break;
    case "unbinding":
      validateUnbinding(b, errors);
      break;
    default:
      errors.push("event_type.unknown");
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as ApurBody };
}

// ── §4.1 binding ──────────────────────────────────────────────────────────────

function validateBinding(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.activity_id_commit)) errors.push("activity_id_commit.missing");
  if (!isNonEmptyString(b.purpose_commit)) errors.push("purpose_commit.missing");
  if (!isNonEmptyString(b.purpose_class)) errors.push("purpose_class.missing");
  if (!isNonEmptyString(b.lawful_basis)) errors.push("lawful_basis.missing");
  validateDataCategories(b.data_categories, errors);
  if (!isNonEmptyString(b.data_subjects_class)) errors.push("data_subjects_class.missing");
  if (!isNonEmptyString(b.policy_hash)) errors.push("policy_hash.missing");
  if (!isNonEmptyString(b.minimisation_hash)) errors.push("minimisation_hash.missing");
  if (!isNonEmptyString(b.bound_at)) errors.push("bound_at.missing");
  // Nullable refs: null or non-empty string
  validateNullableRef(b.consent_receipt_hash, "consent_receipt_hash", errors);
  validateNullableRef(b.retention_receipt_hash, "retention_receipt_hash", errors);
  validateNullableRef(b.transfer_arrangement_hash, "transfer_arrangement_hash", errors);
}

// ── §4.2 repurpose ────────────────────────────────────────────────────────────

const COMPAT_CONCLUSIONS = new Set<string>([
  "compatible",
  "incompatible_requires_new_basis",
  "incompatible_aborted",
]);

function validateRepurpose(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.new_purpose_commit)) errors.push("new_purpose_commit.missing");
  if (!isNonEmptyString(b.new_purpose_class)) errors.push("new_purpose_class.missing");
  if (!isNonEmptyString(b.compat_link_hash)) errors.push("compat_link_hash.missing");
  if (!isNonEmptyString(b.compat_context_hash)) errors.push("compat_context_hash.missing");
  if (!isNonEmptyString(b.compat_subjects_reasonable_hash)) {
    errors.push("compat_subjects_reasonable_hash.missing");
  }
  if (!isNonEmptyString(b.compat_consequences_hash)) errors.push("compat_consequences_hash.missing");
  if (!isNonEmptyString(b.compat_safeguards_hash)) errors.push("compat_safeguards_hash.missing");
  if (b.compat_conclusion === undefined || b.compat_conclusion === null) {
    errors.push("compat_conclusion.missing");
  } else if (typeof b.compat_conclusion !== "string" || !COMPAT_CONCLUSIONS.has(b.compat_conclusion)) {
    errors.push("compat_conclusion.invalid");
  }
  if (!isNonEmptyString(b.minimisation_hash)) errors.push("minimisation_hash.missing");
  if (!isNonEmptyString(b.tested_at)) errors.push("tested_at.missing");
}

// ── §4.3 unbinding ────────────────────────────────────────────────────────────

const UNBINDING_REASONS = new Set<string>([
  "purpose_fulfilled",
  "consent_withdrawn",
  "controller_decision",
  "retention_expired",
  "subject_request_art17",
  "regulator_order",
  "mechanism_struck_down",
]);

function validateUnbinding(b: Record<string, unknown>, errors: string[]): void {
  if (b.reason === undefined || b.reason === null) {
    errors.push("reason.missing");
  } else if (typeof b.reason !== "string" || !UNBINDING_REASONS.has(b.reason)) {
    errors.push("reason.invalid");
  }
  if (!isNonEmptyString(b.unbound_at)) errors.push("unbound_at.missing");
  // Nullable ref
  validateNullableRef(b.downstream_arr_receipt_hash, "downstream_arr_receipt_hash", errors);
}

// ── Shared validators ─────────────────────────────────────────────────────────

function validateDataCategories(v: unknown, errors: string[]): void {
  if (!Array.isArray(v)) {
    errors.push("data_categories.invalid");
    return;
  }
  if (v.length === 0) {
    errors.push("data_categories.invalid");
    return;
  }
  for (const item of v) {
    if (typeof item !== "string") {
      errors.push("data_categories.invalid");
      return;
    }
  }
}

function validateNullableRef(
  v: unknown,
  field: string,
  errors: string[],
): void {
  if (v === null || v === undefined) return; // null is valid
  if (typeof v !== "string") {
    errors.push(`${field}.invalid`);
  }
}

// ── Shape predicates ──────────────────────────────────────────────────────────

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

// Re-export variant interfaces so callers narrowing on event_type get per-variant
// shapes without reaching into ./types.ts.
export type {
  ApurBindingBody,
  ApurRepurposeBody,
  ApurUnbindingBody,
} from "./types.ts";
