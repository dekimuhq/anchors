/**
 * `gdpr.art47.bcr_authorised` profile validator — ATR spec §5.5.
 *
 * Hook: GDPR Art 47 — transfer on the basis of binding corporate rules that
 * have received supervisory-authority authorisation. On `arrangement` events
 * the receipt MUST indicate whether the BCR covers controllers or processors
 * and that it is DPA-authorised.
 *
 * v1 invariants enforced here:
 *   - On `arrangement` events: `body.mechanism_version` MUST be
 *     `bcr-c-authorised` or `bcr-p-authorised`.
 *   - All other event types: pass through (no errors).
 */

import type { AtrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART47_BCR_AUTHORISED_PROFILE_ID =
  "gdpr.art47.bcr_authorised" as const;

const VALID_BCR_AUTH_VERSIONS: ReadonlySet<string> = new Set([
  "bcr-c-authorised",
  "bcr-p-authorised",
]);

export function validateGdprArt47BcrAuthorised(
  body: AtrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "arrangement") {
    return { errors };
  }

  if (!VALID_BCR_AUTH_VERSIONS.has(body.mechanism_version)) {
    errors.push("gdpr.art47.bcr_authorised.mechanism_version_invalid");
  }

  return { errors };
}

export const validateGdprArt47BcrAuthorisedProfile = makeProfileAdapter(
  GDPR_ART47_BCR_AUTHORISED_PROFILE_ID,
  (body) => validateGdprArt47BcrAuthorised(body as AtrBody),
);
