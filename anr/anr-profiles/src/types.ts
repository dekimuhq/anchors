/**
 * Shared types for ANR v1 profile validators (spec §5).
 *
 * Each per-profile module exports a pure `validate*` function returning a
 * `ProfileValidationResult` AND an adapter `*ProfileValidator` matching the
 * universal `ProfileValidator` signature from `@dekimuhq/anchors-envelope`.
 *
 * Pure validators MUST be side-effect-free and import-cycle-free; they take
 * a typed `AnrBody` (re-exported from `./body-types.ts`) and a small
 * context surface. Adapters wrap them into the verifier-facing shape.
 */

import type { AnrProfile } from "./body-types.ts";

/**
 * Result of a pure profile validator. Errors are stable machine-readable
 * dot-separated codes prefixed with the profile id (e.g.
 * `notice.art13.collected_direct.rights_surface.missing:art17`).
 */
export interface ProfileValidationResult {
  errors: string[];
}

/**
 * Verifier-derived context surface available to ANR profile validators.
 *
 * Mirrors the relevant subset of `ProfileValidatorCtx` from
 * `@dekimuhq/anchors-envelope`. Declared locally so pure validators do not
 * pull the envelope package into their type surface — adapter wrappers
 * marshal between the two.
 */
export interface AnrProfileCtx {
  /** TSA verification reason (e.g. `"tsa_verified"`, `"tsa_absent"`). */
  tsa_state?: string;
  /** True iff the TSA was matched against a trust-list anchor (e.g. EUTL). */
  tsa_listed?: boolean;
  /** TSA policy OID parsed from the TSTInfo, if available. */
  tsa_policy_oid?: string;
}

/**
 * Discriminator over the 5 v1 profile ids. Re-exported from `./body-types.ts` (which now owns the leaf) so
 * downstream packages can pin the ID set without importing the verifier.
 */
export type { AnrProfile };
