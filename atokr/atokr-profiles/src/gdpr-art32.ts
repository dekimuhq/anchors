/**
 * `tokenization.gdpr.art32` profile validator — ATokR spec §5.1.
 *
 * Hook: GDPR Art 32 — security of processing. Tokenization is presented as
 * a pseudonymisation/encryption measure. The receipt MUST attest the purpose
 * for which the token scope was created.
 *
 * v1 invariants enforced here:
 *   - `body.scope.purpose` MUST be a non-empty string.
 */

import type { AtokrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART32_PROFILE_ID = "tokenization.gdpr.art32" as const;

export function validateGdprArt32(body: AtokrBody): ProfileValidationResult {
  const errors: string[] = [];

  const purpose = (body as unknown as Record<string, unknown>);
  const scope = purpose["scope"] as Record<string, unknown> | undefined;
  const purposeValue = scope?.["purpose"];

  if (typeof purposeValue !== "string" || purposeValue.trim() === "") {
    errors.push("tokenization.gdpr.art32.purpose_missing");
  }

  return { errors };
}

export const validateGdprArt32Profile = makeProfileAdapter(
  GDPR_ART32_PROFILE_ID,
  (body) => validateGdprArt32(body as AtokrBody),
);
