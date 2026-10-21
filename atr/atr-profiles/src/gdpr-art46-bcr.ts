/**
 * `gdpr.art46.bcr` profile validator — ATR spec §5.3.
 *
 * Hook: GDPR Art 46 — transfer subject to appropriate safeguards (BCRs,
 * non-authorised). On `arrangement` events the receipt MUST name whether the
 * BCR covers controllers (`bcr-c`) or processors (`bcr-p`).
 *
 * v1 invariants enforced here:
 *   - On `arrangement` events: `body.mechanism_version` MUST be `bcr-c` or
 *     `bcr-p`.
 *   - All other event types: pass through (no errors).
 */

import type { AtrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART46_BCR_PROFILE_ID = "gdpr.art46.bcr" as const;

const VALID_BCR_VERSIONS: ReadonlySet<string> = new Set(["bcr-c", "bcr-p"]);

export function validateGdprArt46Bcr(body: AtrBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "arrangement") {
    return { errors };
  }

  if (!VALID_BCR_VERSIONS.has(body.mechanism_version)) {
    errors.push("gdpr.art46.bcr.mechanism_version_invalid");
  }

  return { errors };
}

export const validateGdprArt46BcrProfile = makeProfileAdapter(
  GDPR_ART46_BCR_PROFILE_ID,
  (body) => validateGdprArt46Bcr(body as AtrBody),
);
