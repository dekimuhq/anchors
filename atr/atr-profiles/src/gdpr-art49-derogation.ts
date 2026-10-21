/**
 * `gdpr.art49.derogation` profile validator — ATR spec §5.6.
 *
 * Hook: GDPR Art 49 — derogations for specific situations (per-transfer basis).
 * Structural validation only in v1. The consent_receipt_hash linkage rule is a
 * §7.2 cross-receipt check enforced by the verifier, not the profile validator.
 *
 * v1 invariants enforced here:
 *   - Pass through for all event types — no errors in v1.
 */

import type { AtrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART49_DEROGATION_PROFILE_ID =
  "gdpr.art49.derogation" as const;

export function validateGdprArt49Derogation(
  _body: AtrBody,
): ProfileValidationResult {
  return { errors: [] };
}

export const validateGdprArt49DerogationProfile = makeProfileAdapter(
  GDPR_ART49_DEROGATION_PROFILE_ID,
  (body) => validateGdprArt49Derogation(body as AtrBody),
);
