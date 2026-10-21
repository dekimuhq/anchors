/**
 * AIR (Anchored Impact-Assessment Receipts) type surface.
 *
 * The body-shape types (`AirBody` and its eleven variants, `AirProfile`, the
 * claim/event-type and closed sub-field enums) are defined canonically in
 * `@dekimuhq/air-profiles` (`./body.ts` there) and re-exported here. They were
 * relocated so the profile validators can import the body shape without a
 * profiles→verifier import cycle (the verifier imports profile *values* in
 * `family.ts`). `@dekimuhq/air` re-exports every body symbol, so its
 * public type API is unchanged for downstream consumers.
 *
 * Only the chain-walker depth-limit constants — verifier-internal values, not
 * part of the body shape — remain defined in this package.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/air.
 * Family invariants: `meta/FAMILY-CONSISTENCY.md` (chip #13,
 * subject-presence per-event split — `null` everywhere except OPTIONALLY
 * on `dpia.stakeholders_consulted` per D10-AIR-6 — and Status List 2021
 * consumer #7 with the `active | closed | withdrawn | revoked` state set
 * per spec §6.3).
 */

import type {
  AirClaimType,
  AirEventType,
  AirProfile,
  AirResidualRiskLevel,
  AirConsultationMethod,
  AirReviewOutcome,
  AirTerminalDisposition,
  AirStatusState,
  AirThresholdTriggeredBody,
  AirScopeLockedBody,
  AirDpoAdvisedBody,
  AirStakeholdersConsultedBody,
  AirCompletedBody,
  AirReviewedBody,
  AirPriorConsultationInitiatedBody,
  AirPriorConsultationResolvedBody,
  AirProcessingAuthorisedBody,
  AirProcessingBlockedBody,
  AirTerminatedBody,
  AirBody,
} from "@dekimuhq/air-profiles";

export type {
  AirClaimType,
  AirEventType,
  AirProfile,
  AirResidualRiskLevel,
  AirConsultationMethod,
  AirReviewOutcome,
  AirTerminalDisposition,
  AirStatusState,
  AirThresholdTriggeredBody,
  AirScopeLockedBody,
  AirDpoAdvisedBody,
  AirStakeholdersConsultedBody,
  AirCompletedBody,
  AirReviewedBody,
  AirPriorConsultationInitiatedBody,
  AirPriorConsultationResolvedBody,
  AirProcessingAuthorisedBody,
  AirProcessingBlockedBody,
  AirTerminatedBody,
  AirBody,
};

// ── Chain walker depth limits (spec §6.2) ─────────────────────────────────────

/** Default cap on the number of envelope-`prev` hops the walker traverses. */
export const AIR_DEFAULT_DEPTH_LIMIT = 256;

/** Floor for the depth-limit option; values below this are clamped up. */
export const AIR_DEPTH_LIMIT_MIN = 32;

/** Ceiling for the depth-limit option; values above this are clamped down. */
export const AIR_DEPTH_LIMIT_MAX = 1024;
