/**
 * Shared validator surface for AIR v1 regulatory profile checks (spec §5 + §F).
 *
 * Each per-profile validator (`./art35_3_a.ts` etc.) accepts a single
 * `ProfileValidatorInput` and returns a `ProfileValidationResult`. Profile
 * structural conformance — base body shape, per-event required fields,
 * pinned-null cross-event fields, the `consultation_output_empty`
 * HARD-invalid — is enforced by `@dekimuhq/air`'s `verifyAirBody`
 * (§C). Profile validators add the regulatory recommendations the AIR spec
 * surfaces as HARD `errors` or informational `warnings`.
 *
 * Single-receipt scope: validators consume one envelope-body pair at a time.
 * Chain-level surfaces (e.g. `voluntary_high_risk_no_consultation`,
 * `public_monitoring_stakeholder_missing`) are out of scope here and live
 * with the air-verifier chain walker (`./chain.ts`).
 *
 * Result discipline:
 * - `errors`: HARD invalid — receipt MUST be rejected.
 * - `warnings`: informational — surfaced to operators, NOT a rejection
 *   reason. The AIR spec uses warnings extensively for "SHOULD" guidance
 *   that supervisory authorities expect controllers to honour absent good
 *   reason but does NOT make a v1 conformance failure.
 */

import type { AirBody, AirProfile } from "./body.ts";

/**
 * Single-receipt input to every profile validator.
 *
 * `iat` is the envelope-level issuance timestamp (ISO 8601 UTC) — required
 * by the review-window checks on §5.1 and §5.5. Pass the envelope `iat`
 * verbatim; pass `null` when the caller does not have it (review-window
 * warnings are then skipped).
 */
export interface ProfileValidatorInput {
  body: AirBody;
  iat: string | null;
}

/**
 * Output of every profile validator.
 *
 * `valid` is `true` iff `errors` is empty; warnings do not invalidate the
 * receipt. Matches the ARR/ACR profile surface in spirit but adds
 * `warnings` because AIR's §5 leans heavily on SHOULD-grade guidance.
 */
export interface ProfileValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/** Functional shape of every per-profile validator. */
export type ProfileValidator = (input: ProfileValidatorInput) => ProfileValidationResult;

/** Stable, machine-readable error codes a validator may emit. */
export const AIR_PROFILE_ERROR_CODES = {
  /** The caller supplied a body whose context contradicts the profile validator dispatched. */
  PROFILE_MISMATCH: "profile.mismatch",
} as const;

/** Stable, machine-readable warning codes (spec §5 surface). */
export const AIR_PROFILE_WARNING_CODES = {
  // §5.1 art35_3_a_automated_decisions
  ART35_3A_AER_LINK_MISSING: "art35_3a_aer_link_missing",
  REVIEW_WINDOW_LONG: "review_window_long",
  // §5.2 art35_3_b_large_scale_special_categories
  ART35_3B_ALR_LINK_MISSING: "art35_3b_alr_link_missing",
  // §5.5 voluntary
  REVIEW_WINDOW_LONG_VOLUNTARY: "review_window_long_voluntary",
} as const;

/** Closed set of v1 profile identifiers — re-exported for callers. */
export const AIR_V1_PROFILES: readonly AirProfile[] = [
  "impact.art35_3_a_automated_decisions",
  "impact.art35_3_b_large_scale_special_categories",
  "impact.art35_3_c_public_monitoring",
  "impact.art35_4_dpa_list",
  "impact.voluntary",
] as const;

// ── Shared helpers (used by every per-profile validator) ─────────────────────

/**
 * Approximate month length in milliseconds. AIR §5.1 / §5.5 review-window
 * caps are SHOULD-grade ("≤12 months", "≤36 months"); precision to the day
 * is not required. Matches the calculus the ARR `aiact-art10` profile uses
 * (`365.25 * 86_400_000` for a year).
 */
const DAYS_PER_MONTH = 30.4375;
const MS_PER_DAY = 86_400_000;
export const AIR_MONTH_MS = DAYS_PER_MONTH * MS_PER_DAY;

/** Months in the strict review window for high-risk profiles (§5.1). */
export const AIR_REVIEW_WINDOW_MONTHS_STRICT = 12;

/** Months in the looser review window for the voluntary profile (§5.5). */
export const AIR_REVIEW_WINDOW_MONTHS_VOLUNTARY = 36;

/**
 * Parse an ISO 8601 timestamp returning Unix-ms, or `null` if the string is
 * not a parseable timestamp. The AIR spec uses ISO 8601 UTC throughout; we
 * defer to `Date.parse` which accepts the full range RFC 3339 covers.
 */
export function parseTimestamp(s: string | null | undefined): number | null {
  if (typeof s !== "string" || s.length === 0) return null;
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? null : ms;
}

/** True iff `v` is an array of one or more non-empty strings. */
export function isNonEmptyStringArray(v: unknown): v is readonly string[] {
  if (!Array.isArray(v) || v.length === 0) return false;
  for (const item of v) {
    if (typeof item !== "string" || item.length === 0) return false;
  }
  return true;
}
