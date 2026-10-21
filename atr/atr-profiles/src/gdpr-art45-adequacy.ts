/**
 * `gdpr.art45.adequacy` profile validator — ATR spec §5.1.
 *
 * Hook: GDPR Art 45 — transfer on the basis of an adequacy decision.
 * On `arrangement` events the receipt MUST attest the adequacy decision by
 * naming the target country via `mechanism_version` in the form
 * `adequacy:<CC>` (ISO 3166-1 alpha-2 country code, upper-case).
 *
 * v1 invariants enforced here:
 *   - On `arrangement` events: `body.mechanism_version` MUST match
 *     `/^adequacy:[A-Z]{2}$/`.
 *   - All other event types: pass through (no errors).
 */

import type { AtrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART45_ADEQUACY_PROFILE_ID = "gdpr.art45.adequacy" as const;

const ADEQUACY_PATTERN = /^adequacy:[A-Z]{2}$/;

export function validateGdprArt45Adequacy(
  body: AtrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "arrangement") {
    return { errors };
  }

  if (!ADEQUACY_PATTERN.test(body.mechanism_version)) {
    errors.push("gdpr.art45.adequacy.mechanism_version_invalid");
  }

  return { errors };
}

export const validateGdprArt45AdequacyProfile = makeProfileAdapter(
  GDPR_ART45_ADEQUACY_PROFILE_ID,
  (body) => validateGdprArt45Adequacy(body as AtrBody),
);
