/**
 * Profile §5.3 — `impact.art35_3_c_public_monitoring`.
 *
 * GDPR Art. 35(3)(c): systematic monitoring of publicly accessible areas on
 * a large scale.
 *
 * v1 single-receipt surfaces:
 *
 * - No per-event HARD or WARN surface is emitted from a single receipt.
 *   `dpia.completed.body.alr_receipt_ids` is MAY-grade in §5.3 (not SHOULD)
 *   so absence is not surfaced.
 *
 * - The §5.3 informational warning `public_monitoring_stakeholder_missing`
 *   ("DPIA chain SHOULD include a `dpia.stakeholders_consulted` event")
 *   is a chain-level surface enforced by the air-verifier chain walker, not
 *   a single-receipt concern. We do NOT surface it here even when the body
 *   is `dpia.completed` because we cannot see prior events.
 *
 * The validator is intentionally minimal — its job is to confirm the v1
 * profile id is in the registry. If §5.3 grows a single-receipt obligation
 * in v1.1, this is where it lands without disturbing callers.
 */

import {
  type ProfileValidationResult,
  type ProfileValidatorInput,
} from "./types.ts";

export const ART35_3_C_PROFILE_ID = "impact.art35_3_c_public_monitoring" as const;

export function validateImpactArt35_3_c(
  _input: ProfileValidatorInput,
): ProfileValidationResult {
  return { valid: true, errors: [], warnings: [] };
}
