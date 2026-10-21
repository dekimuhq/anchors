/**
 * Profile §5.2 — `impact.art35_3_b_large_scale_special_categories`.
 *
 * GDPR Art. 35(3)(b): large-scale processing of special categories (Art. 9)
 * or criminal-offence data (Art. 10).
 *
 * v1 single-receipt surfaces:
 *
 * - On `dpia.completed`:
 *   - `body.alr_receipt_ids` SHOULD be a non-empty array of ALR receipt ids
 *     mapping the data flows of special-category data in scope (§5.2 + §8.3).
 *     Absent or empty → warning `art35_3b_alr_link_missing`. Not HARD-invalid
 *     because some DPIAs precede full lineage anchoring.
 *
 * Cross-border `atr_receipt_ids` SHOULD be populated when the processing
 * crosses borders, but that condition is invisible to a single-receipt
 * validator (the receipt does not carry a "cross_border" flag). Surfacing
 * that warning belongs at the chain walker or organisational policy layer.
 *
 * - Every other event_type: no profile-specific surface in v1.
 */

import type { AirBody } from "./body.ts";
import {
  AIR_PROFILE_WARNING_CODES,
  isNonEmptyStringArray,
  type ProfileValidationResult,
  type ProfileValidatorInput,
} from "./types.ts";

export const ART35_3_B_PROFILE_ID =
  "impact.art35_3_b_large_scale_special_categories" as const;

export function validateImpactArt35_3_b(
  input: ProfileValidatorInput,
): ProfileValidationResult {
  const { body } = input;
  const errors: string[] = [];
  const warnings: string[] = [];

  if (body.event_type === "dpia.completed") {
    checkCompleted(body, warnings);
  }

  return { valid: errors.length === 0, errors, warnings };
}

function checkCompleted(
  body: Extract<AirBody, { event_type: "dpia.completed" }>,
  warnings: string[],
): void {
  if (!isNonEmptyStringArray(body.alr_receipt_ids)) {
    warnings.push(AIR_PROFILE_WARNING_CODES.ART35_3B_ALR_LINK_MISSING);
  }
}
