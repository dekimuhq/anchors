/**
 * `schremsii.tia` profile validator — ATR spec §5.8.
 *
 * Hook: Schrems II Transfer Impact Assessment. On `tia` events the receipt
 * MUST carry a valid assessment outcome and at least one surveillance-law
 * reference.
 *
 * v1 invariants enforced here:
 *   - On `tia` events: `body.assessment_outcome` MUST be one of
 *     `permitted_plain`, `permitted_with_supplementary`, `not_permitted`.
 *   - On `tia` events: `body.surveillance_law_refs` MUST be a non-empty array.
 *   - All other event types: pass through (no errors).
 */

import type { AtrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const SCHREMSII_TIA_PROFILE_ID = "schremsii.tia" as const;

const VALID_OUTCOMES: ReadonlySet<string> = new Set([
  "permitted_plain",
  "permitted_with_supplementary",
  "not_permitted",
]);

export function validateSchremsiiTia(body: AtrBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "tia") {
    return { errors };
  }

  if (!VALID_OUTCOMES.has(body.assessment_outcome)) {
    errors.push("schremsii.tia.assessment_outcome_invalid");
  }

  if (
    !Array.isArray(body.surveillance_law_refs) ||
    body.surveillance_law_refs.length === 0
  ) {
    errors.push("schremsii.tia.surveillance_law_refs_invalid");
  }

  return { errors };
}

export const validateSchremsiiTiaProfile = makeProfileAdapter(
  SCHREMSII_TIA_PROFILE_ID,
  (body) => validateSchremsiiTia(body as AtrBody),
);
