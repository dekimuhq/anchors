/**
 * Shared types for ATokR v1 profile validators (spec §5).
 *
 * Each per-profile module exports a pure `validate*` function returning a
 * `ProfileValidationResult` AND an adapter `*Profile` matching the universal
 * `ProfileValidator` signature from `@dekimuhq/anchors-envelope`.
 */

import type { AtokrProfile } from "./body.ts";

/**
 * Result of a pure profile validator. Errors are stable machine-readable
 * dot-separated codes prefixed with the profile id.
 */
export interface ProfileValidationResult {
  errors: string[];
}

/**
 * Verifier-derived context surface available to ATokR profile validators.
 */
export interface AtokrProfileCtx {
  /** TSA verification reason (e.g. `"tsa_verified"`, `"tsa_absent"`). */
  tsa_state?: string;
  /** True iff the TSA was matched against a trust-list anchor. */
  tsa_listed?: boolean;
  /** TSA policy OID parsed from the TSTInfo, if available. */
  tsa_policy_oid?: string;
}

/**
 * Discriminator over the 5 v1 profile ids. Re-exported from the verifier so
 * downstream packages can pin the ID set without importing both packages.
 */
export type { AtokrProfile };
