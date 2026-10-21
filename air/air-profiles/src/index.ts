/**
 * `@dekimuhq/air-profiles` — regulation profile validators for AIR v1
 * (`ar.impact.v1`).
 *
 * Single-receipt validators for the five spec §5 profiles plus the §F
 * dispatcher. Pair with `@dekimuhq/air`'s `verifyAirBody` (§C)
 * which handles structural / body-shape conformance.
 */

export * from "./body.ts";

export {
  AIR_MONTH_MS,
  AIR_PROFILE_ERROR_CODES,
  AIR_PROFILE_WARNING_CODES,
  AIR_REVIEW_WINDOW_MONTHS_STRICT,
  AIR_REVIEW_WINDOW_MONTHS_VOLUNTARY,
  AIR_V1_PROFILES,
  isNonEmptyStringArray,
  parseTimestamp,
} from "./types.ts";
export type {
  ProfileValidationResult,
  ProfileValidator,
  ProfileValidatorInput,
} from "./types.ts";

export { ART35_3_A_PROFILE_ID, validateImpactArt35_3_a } from "./art35_3_a.ts";
export { ART35_3_B_PROFILE_ID, validateImpactArt35_3_b } from "./art35_3_b.ts";
export { ART35_3_C_PROFILE_ID, validateImpactArt35_3_c } from "./art35_3_c.ts";
export { ART35_4_PROFILE_ID, validateImpactArt35_4 } from "./art35_4.ts";
export { VOLUNTARY_PROFILE_ID, validateImpactVoluntary } from "./voluntary.ts";

export {
  REGISTERED_AIR_PROFILES,
  getAirProfileValidator,
  validateAirProfile,
} from "./dispatcher.ts";
