/**
 * Universal-signature adapters for the six regulated retention profile
 * validators, so they dispatch from any verifier via the `profileValidators`
 * option (mirrors `gdpr-art17-finalized-adapter.ts`).
 *
 * The underlying validators (`validateGdprArt5e`, …) are v1-shaped: they read
 * `r.kind`, `r.trigger`, `r.event_at` and profile-specific attributes off the
 * receipt root. v=2 receipts carry `kind` at the envelope level (`claim_type`)
 * and profile attributes under `body.profile_attributes`, so `toReceipt`
 * reconstructs the flat receipt shape the validators expect. The validators
 * themselves are unchanged.
 *
 * Profile validation is advisory — an `ok: false` entry never poisons
 * `signature_valid` (factory invariant).
 */

import type { Envelope, ProfileValidator, ProfileStateEntry } from "@dekimuhq/anchors-envelope";
import type { AnyARRReceipt } from "./body-types.ts";
import type { ProfileValidationResult } from "./gdpr-art17.ts";
import { validateGdprArt5e } from "./gdpr-art5e.ts";
import { validateHipaaRetention } from "./hipaa-retention.ts";
import { validateKycRetention } from "./kyc-retention.ts";
import { validateSoxRetention } from "./sox-retention.ts";
import { validateMifid2Retention } from "./mifid2-retention.ts";
import { validateAiActArt10 } from "./aiact-art10.ts";

export const GDPR_ART5E_PROFILE_ID = "arr.gdpr.art5e" as const;
export const HIPAA_RETENTION_PROFILE_ID = "arr.hipaa.retention" as const;
export const KYC_RETENTION_PROFILE_ID = "arr.kyc.retention" as const;
export const SOX_RETENTION_PROFILE_ID = "arr.sox.retention" as const;
export const MIFID2_RETENTION_PROFILE_ID = "arr.mifid2.retention" as const;
export const AIACT_ART10_PROFILE_ID = "arr.aiact.art10" as const;

/**
 * Reconstruct the flat AnyARRReceipt shape the v1-shaped validators read from a
 * v=2 envelope + body: inject `kind` from `claim_type`, hoist
 * `body.profile_attributes` to the root.
 */
function toReceipt(envelope: Envelope, body: unknown): AnyARRReceipt {
  const b = (body ?? {}) as Record<string, unknown>;
  const attrs = (b.profile_attributes ?? {}) as Record<string, unknown>;
  return {
    ...b,
    ...attrs,
    kind: envelope.claim_type,
  } as unknown as AnyARRReceipt;
}

function toEntry(profile_id: string, result: ProfileValidationResult): ProfileStateEntry {
  if (result.errors.length === 0) return { profile_id, ok: true };
  return { profile_id, ok: false, reason: result.errors.join(",") };
}

export const validateGdprArt5eProfile: ProfileValidator = (envelope, body) =>
  toEntry(GDPR_ART5E_PROFILE_ID, validateGdprArt5e(toReceipt(envelope, body)));

export const validateHipaaRetentionProfile: ProfileValidator = (envelope, body) =>
  toEntry(HIPAA_RETENTION_PROFILE_ID, validateHipaaRetention(toReceipt(envelope, body)));

export const validateKycRetentionProfile: ProfileValidator = (envelope, body) =>
  toEntry(KYC_RETENTION_PROFILE_ID, validateKycRetention(toReceipt(envelope, body)));

export const validateSoxRetentionProfile: ProfileValidator = (envelope, body) =>
  toEntry(SOX_RETENTION_PROFILE_ID, validateSoxRetention(toReceipt(envelope, body)));

export const validateMifid2RetentionProfile: ProfileValidator = (envelope, body) =>
  toEntry(MIFID2_RETENTION_PROFILE_ID, validateMifid2Retention(toReceipt(envelope, body)));

export const validateAiActArt10Profile: ProfileValidator = (envelope, body) =>
  toEntry(AIACT_ART10_PROFILE_ID, validateAiActArt10(toReceipt(envelope, body)));
