/**
 * Profile §5.4 — `impact.art35_4_dpa_list`.
 *
 * Processing on the DPA's Article 35(4) "always required" list — per
 * jurisdiction.
 *
 * v1 single-receipt surfaces:
 *
 * - The spec §5.4 reserves a `body.dpa_list_reference` field
 *   (`<DPA>:list-<YYYY-MM-DD>#<entry>`) and a `body.dpa_jurisdiction` on
 *   `dpia.threshold_triggered`. Neither is present in the v1 AIR body
 *   discriminated union (`dpa_jurisdiction` is pinned to `null` on every
 *   non-`prior_consultation_initiated` event in v1). Both fields are
 *   deferred to a future v1.1 amendment.
 *
 * - For v1, the validator is intentionally a no-op beyond confirming the
 *   profile id is registered. Promoting §5.4 to surface its own warnings
 *   requires (a) the v1.1 amendment landing the body fields and (b) a
 *   per-DPA list registry to validate `dpa_list_reference` against.
 *
 * Holding the validator here (rather than deleting it) keeps the §F
 * dispatcher surface symmetric across the five profiles and lets v1.1
 * extend without breaking the public API.
 */

import {
  type ProfileValidationResult,
  type ProfileValidatorInput,
} from "./types.ts";

export const ART35_4_PROFILE_ID = "impact.art35_4_dpa_list" as const;

export function validateImpactArt35_4(
  _input: ProfileValidatorInput,
): ProfileValidationResult {
  return { valid: true, errors: [], warnings: [] };
}
