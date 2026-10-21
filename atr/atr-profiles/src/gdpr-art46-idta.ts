/**
 * `gdpr.art46.idta` profile validator — ATR spec §5.4.
 *
 * Hook: GDPR Art 46 — transfer subject to appropriate safeguards (IDTA /
 * UK Addendum). On `arrangement` events the receipt MUST name whether the
 * transfer relies on the 2022 IDTA itself or the UK Addendum.
 *
 * v1 invariants enforced here:
 *   - On `arrangement` events: `body.mechanism_version` MUST be `idta-2022`
 *     or `addendum-2022`.
 *   - All other event types: pass through (no errors).
 */

import type { AtrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART46_IDTA_PROFILE_ID = "gdpr.art46.idta" as const;

const VALID_IDTA_VERSIONS: ReadonlySet<string> = new Set([
  "idta-2022",
  "addendum-2022",
]);

export function validateGdprArt46Idta(body: AtrBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "arrangement") {
    return { errors };
  }

  if (!VALID_IDTA_VERSIONS.has(body.mechanism_version)) {
    errors.push("gdpr.art46.idta.mechanism_version_invalid");
  }

  return { errors };
}

export const validateGdprArt46IdtaProfile = makeProfileAdapter(
  GDPR_ART46_IDTA_PROFILE_ID,
  (body) => validateGdprArt46Idta(body as AtrBody),
);
