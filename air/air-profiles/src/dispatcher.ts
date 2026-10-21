/**
 * §F profile-validator dispatcher.
 *
 * Resolves an `AirProfile` literal to the matching per-profile validator,
 * then invokes it. Unknown profile strings produce a `profile.unknown`
 * HARD error — air-verifier rejects unregistered profile strings at the
 * envelope level (`isAirProfile`), but the dispatcher is defensive so
 * callers passing untrusted data still get a stable failure mode.
 */

import type { AirProfile } from "./body.ts";
import {
  ART35_3_A_PROFILE_ID,
  validateImpactArt35_3_a,
} from "./art35_3_a.ts";
import {
  ART35_3_B_PROFILE_ID,
  validateImpactArt35_3_b,
} from "./art35_3_b.ts";
import {
  ART35_3_C_PROFILE_ID,
  validateImpactArt35_3_c,
} from "./art35_3_c.ts";
import { ART35_4_PROFILE_ID, validateImpactArt35_4 } from "./art35_4.ts";
import {
  VOLUNTARY_PROFILE_ID,
  validateImpactVoluntary,
} from "./voluntary.ts";
import {
  type ProfileValidationResult,
  type ProfileValidator,
  type ProfileValidatorInput,
} from "./types.ts";

const REGISTRY: ReadonlyMap<AirProfile, ProfileValidator> = new Map<
  AirProfile,
  ProfileValidator
>([
  [ART35_3_A_PROFILE_ID, validateImpactArt35_3_a],
  [ART35_3_B_PROFILE_ID, validateImpactArt35_3_b],
  [ART35_3_C_PROFILE_ID, validateImpactArt35_3_c],
  [ART35_4_PROFILE_ID, validateImpactArt35_4],
  [VOLUNTARY_PROFILE_ID, validateImpactVoluntary],
]);

/**
 * Dispatch a single-receipt profile validation.
 *
 * Pass the envelope-level `profile` literal and a `ProfileValidatorInput`
 * built from the same envelope's `body` + `iat`. Returns the validator's
 * `ProfileValidationResult` directly; on unknown profile produces
 * `valid: false, errors: ["profile.unknown"]`.
 */
export function validateAirProfile(
  profile: string,
  input: ProfileValidatorInput,
): ProfileValidationResult {
  const validator = REGISTRY.get(profile as AirProfile);
  if (validator === undefined) {
    return { valid: false, errors: ["profile.unknown"], warnings: [] };
  }
  return validator(input);
}

/**
 * Lookup the validator function for a known profile id. Returns `undefined`
 * for unknown ids; callers SHOULD prefer `validateAirProfile` unless they
 * need to capture the function reference (e.g. for batched evaluation).
 */
export function getAirProfileValidator(
  profile: AirProfile,
): ProfileValidator | undefined {
  return REGISTRY.get(profile);
}

/** Closed list of registered profile ids — useful for table-driven tests. */
export const REGISTERED_AIR_PROFILES: readonly AirProfile[] = [
  ART35_3_A_PROFILE_ID,
  ART35_3_B_PROFILE_ID,
  ART35_3_C_PROFILE_ID,
  ART35_4_PROFILE_ID,
  VOLUNTARY_PROFILE_ID,
];
