/**
 * Profile §5.1 — `impact.art35_3_a_automated_decisions`.
 *
 * GDPR Art. 35(3)(a): systematic and extensive evaluation of personal
 * aspects through automated processing, including profiling, with legal or
 * similarly significant effects.
 *
 * v1 single-receipt surfaces:
 *
 * - On `dpia.completed`:
 *   - `body.aer_receipt_ids` SHOULD be a non-empty array of AER `aer.adm.v1`
 *     receipt ids (§8.1). Absent or empty → warning
 *     `art35_3a_aer_link_missing`. NOT HARD-invalid: pre-deployment DPIAs
 *     legitimately have no AER receipts yet (spec §5.1 + §8.1).
 *   - `body.review_due_at - envelope.iat > 12 months` → warning
 *     `review_window_long` (§5.1: review window SHOULD be ≤12 months).
 *
 * - Every other event_type: no profile-specific surface in v1. The body
 *   verifier (`@dekimuhq/air`'s `verify-single` module) already enforces
 *   structural conformance.
 */

import type { AirBody } from "./body.ts";
import {
  AIR_MONTH_MS,
  AIR_PROFILE_WARNING_CODES,
  AIR_REVIEW_WINDOW_MONTHS_STRICT,
  isNonEmptyStringArray,
  parseTimestamp,
  type ProfileValidationResult,
  type ProfileValidatorInput,
} from "./types.ts";

export const ART35_3_A_PROFILE_ID = "impact.art35_3_a_automated_decisions" as const;

export function validateImpactArt35_3_a(
  input: ProfileValidatorInput,
): ProfileValidationResult {
  const { body, iat } = input;
  const errors: string[] = [];
  const warnings: string[] = [];

  if (body.event_type === "dpia.completed") {
    checkCompleted(body, iat, warnings);
  }

  return { valid: errors.length === 0, errors, warnings };
}

function checkCompleted(
  body: Extract<AirBody, { event_type: "dpia.completed" }>,
  iat: string | null,
  warnings: string[],
): void {
  // §5.1 + §8.1 — AER linkage SHOULD be populated.
  if (!isNonEmptyStringArray(body.aer_receipt_ids)) {
    warnings.push(AIR_PROFILE_WARNING_CODES.ART35_3A_AER_LINK_MISSING);
  }

  // §5.1 — review window SHOULD be ≤12 months.
  const iatMs = parseTimestamp(iat);
  const reviewMs = parseTimestamp(body.review_due_at);
  if (iatMs !== null && reviewMs !== null) {
    const windowMs = reviewMs - iatMs;
    if (windowMs > AIR_REVIEW_WINDOW_MONTHS_STRICT * AIR_MONTH_MS) {
      warnings.push(AIR_PROFILE_WARNING_CODES.REVIEW_WINDOW_LONG);
    }
  }
}
