/**
 * ABR (Anchored Breach Receipts) type surface.
 *
 * The body-shape types (`AbrBody` and its eight variants, `AbrProfile`, the
 * claim/event-type and closed sub-field enums) are defined canonically in
 * `@dekimuhq/abr-profiles` (`./body.ts` there) and re-exported here. They were
 * relocated so the profile validators can import the body shape without a
 * profiles→verifier import cycle (the verifier imports profile *values* in
 * `family.ts`). `@dekimuhq/abr` re-exports every body symbol, so its
 * public type API is unchanged for downstream consumers.
 *
 * Only the chain-walker depth-limit constants — verifier-internal values, not
 * part of the body shape — remain defined in this package.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/abr.
 * Family invariants: `meta/FAMILY-CONSISTENCY.md` (chip #11,
 * subject-presence per-event split, TSA mandate row — `breach.detected`
 * MANDATORY, others RECOMMENDED — and status-list consumer #5).
 */

export type {
  AbrClaimType,
  AbrEventType,
  AbrProfile,
  AbrSeverityClass,
  AbrExemptionGround,
  AbrNotificationPhase,
  AbrStatusState,
  AbrDetectedBody,
  AbrAssessedBody,
  AbrDpaNotifiedBody,
  AbrDpaDelayedBody,
  AbrSubjectNotifiedBody,
  AbrSubjectNotificationExemptedBody,
  AbrContainedBody,
  AbrClosedBody,
  AbrBody,
} from "@dekimuhq/abr-profiles";

// ── Chain walker depth limits (spec §6.2) ─────────────────────────────────────

/** Default cap on the number of envelope-`prev` hops the walker traverses. */
export const ABR_DEFAULT_DEPTH_LIMIT = 256;

/** Floor for the depth-limit option; values below this are clamped up. */
export const ABR_DEPTH_LIMIT_MIN = 32;

/** Ceiling for the depth-limit option; values above this are clamped down. */
export const ABR_DEPTH_LIMIT_MAX = 1024;
