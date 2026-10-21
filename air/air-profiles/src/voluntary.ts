/**
 * Profile §5.5 — `impact.voluntary`.
 *
 * Controller voluntarily performs a DPIA where Art. 35(3)/(4) thresholds
 * are not met. Valid path for high-public-interest processing the
 * controller wishes to govern formally.
 *
 * v1 single-receipt surfaces:
 *
 * - On `dpia.completed`:
 *   - `body.review_due_at - envelope.iat > 36 months` → warning
 *     `review_window_long_voluntary` (§5.5: looser ≤36 months window).
 *
 * - The §5.5 chain-level surface `voluntary_high_risk_no_consultation`
 *   ("voluntary DPIA reaching `residual_risk_level === "high"` SHOULD
 *   still pass through `prior_consultation_initiated`") is a chain-walker
 *   concern — it requires visibility into subsequent events. We do NOT
 *   emit it from a single-receipt validator.
 */

import type { AirBody } from "./body.ts";
import {
  AIR_MONTH_MS,
  AIR_PROFILE_WARNING_CODES,
  AIR_REVIEW_WINDOW_MONTHS_VOLUNTARY,
  parseTimestamp,
  type ProfileValidationResult,
  type ProfileValidatorInput,
} from "./types.ts";

export const VOLUNTARY_PROFILE_ID = "impact.voluntary" as const;

export function validateImpactVoluntary(
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
  const iatMs = parseTimestamp(iat);
  const reviewMs = parseTimestamp(body.review_due_at);
  if (iatMs !== null && reviewMs !== null) {
    const windowMs = reviewMs - iatMs;
    if (windowMs > AIR_REVIEW_WINDOW_MONTHS_VOLUNTARY * AIR_MONTH_MS) {
      warnings.push(AIR_PROFILE_WARNING_CODES.REVIEW_WINDOW_LONG_VOLUNTARY);
    }
  }
}
