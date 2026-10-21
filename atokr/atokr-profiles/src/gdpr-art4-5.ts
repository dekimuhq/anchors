/**
 * `tokenization.gdpr.art4_5` profile validator — ATokR spec §5.2.
 *
 * Hook: GDPR Art 4(5) — pseudonymisation. The receipt MUST attest that the
 * tokenized data and the re-identification key are held separately.
 *
 * v1 invariants enforced here:
 *   - `body.separation_attestation` MUST be present (boolean).
 *   - `body.separation_attestation` MUST be `true`.
 */

import type { AtokrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART4_5_PROFILE_ID = "tokenization.gdpr.art4_5" as const;

export function validateGdprArt4_5(body: AtokrBody): ProfileValidationResult {
  const errors: string[] = [];

  const b = body as unknown as Record<string, unknown>;
  const sa = b["separation_attestation"];

  if (sa === undefined || sa === null) {
    errors.push("tokenization.gdpr.art4_5.separation_attestation.missing");
  } else if (typeof sa !== "boolean") {
    errors.push("tokenization.gdpr.art4_5.separation_attestation.invalid");
  } else if (sa === false) {
    errors.push("tokenization.gdpr.art4_5.separation_not_attested");
  }

  return { errors };
}

export const validateGdprArt4_5Profile = makeProfileAdapter(
  GDPR_ART4_5_PROFILE_ID,
  (body) => validateGdprArt4_5(body as AtokrBody),
);
