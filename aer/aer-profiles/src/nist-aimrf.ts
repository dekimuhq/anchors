/**
 * `nist.aimrf.profile` profile validator — AER spec §5.9.
 *
 * NIST AI Risk Management Framework crosswalk (informational).
 * Maps AI Act conformity evidence to NIST AI RMF governance, map, measure, and manage functions.
 *
 * v1 invariants enforced here:
 *   - `body.event_type === "conformity"` (no additional v1 constraints beyond gate)
 */

import type { AerBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const NIST_AIMRF_PROFILE_ID = "nist.aimrf.profile" as const;

export function validateNistAimrf(body: AerBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "conformity") {
    errors.push("nist.aimrf.profile.wrong_event_type");
  }

  return { errors };
}

export const validateNistAimrfProfile = makeProfileAdapter(
  NIST_AIMRF_PROFILE_ID,
  (body) => validateNistAimrf(body as AerBody),
);
