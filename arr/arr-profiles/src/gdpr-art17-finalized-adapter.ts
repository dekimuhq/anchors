/**
 * Universal-signature adapter for the gdpr.art17.erasure-finalized profile
 * validator.
 *
 * Wraps `validateGdprArt17ErasureFinalized` into the family-wide
 * `ProfileValidator` shape so it can be dispatched from any verifier via
 * the `profileValidators` option.
 *
 * Phase E Task E.2.
 */

import type { ProfileValidator } from "@dekimuhq/anchors-envelope";
import type { TsaReason } from "@dekimuhq/anchors-envelope/tsa";
import {
  validateGdprArt17ErasureFinalized,
  type ErasureFinalizedReceipt,
} from "./gdpr-art17.ts";

export const GDPR_ART17_ERASURE_FINALIZED_PROFILE_ID =
  "arr.gdpr.art17.erasure-finalized" as const;

export const validateGdprArt17ErasureFinalizedProfile: ProfileValidator = (
  _envelope,
  body,
  ctx,
) => {
  const receipt = body as ErasureFinalizedReceipt;
  const result = validateGdprArt17ErasureFinalized(receipt, {
    tsa_state: (ctx.tsa_state ?? "tsa_absent") as TsaReason,
  });
  return {
    profile_id: GDPR_ART17_ERASURE_FINALIZED_PROFILE_ID,
    ok: result.ok,
    ...(result.reason ? { reason: result.reason } : {}),
  };
};
