/**
 * AER v1 types — spec §4 + D10-AER through D15-AER.
 *
 * Claim type: ar.evaluation.v1
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/aer
 *
 * The body-shape types (`AerBody` and its two variants, `AerProfile`, the
 * claim/event-type and closed sub-field enums) are defined canonically in
 * `@dekimuhq/aer-profiles` (`./body.ts` there) and re-exported here. They were
 * relocated so the profile validators can import the body shape without a
 * profiles→verifier import cycle (the verifier imports profile *values* in
 * `family.ts`). `@dekimuhq/aer` re-exports every body symbol, so its
 * public type API is unchanged for downstream consumers.
 *
 * Only the chain-walker depth-limit constants — verifier-internal values, not
 * part of the body shape — remain defined in this package.
 */

import type { AerClaimType, AerEventType, AerProfile, AerRiskClass, AerAssessmentRoute, AerAnnexIiiCategory, AerDisclosureType, AerDisclosureScope, AerWatermarkScheme, AerConformityBody, AerTransparencyBody, AerBody } from "@dekimuhq/aer-profiles";
export type { AerClaimType, AerEventType, AerProfile, AerRiskClass, AerAssessmentRoute, AerAnnexIiiCategory, AerDisclosureType, AerDisclosureScope, AerWatermarkScheme, AerConformityBody, AerTransparencyBody, AerBody };

// ── Chain walker types (spec §7) ────────────────────────────────────────────────

export interface AerChainReceipt {
  id: string;
  iss: string;
  iat: string;
  prev: string | null;
  subject: string | null;
  body: AerBody;
}

export interface AerChainWalkResult {
  ok: boolean;
  hard_invalid_reasons: string[];
  warnings: string[];
}

// ── Depth-limit constants ───────────────────────────────────────────────────────

/** Default cap on the number of envelope-`prev` hops the walker traverses. */
export const AER_DEFAULT_DEPTH_LIMIT = 256;

/** Floor for the depth-limit option; values below this are clamped up. */
export const AER_DEPTH_LIMIT_MIN = 32;

/** Ceiling for the depth-limit option; values above this are clamped down. */
export const AER_DEPTH_LIMIT_MAX = 1024;
