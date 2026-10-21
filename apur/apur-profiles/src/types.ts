/**
 * Shared types for APuR v1 profile validators (spec §5).
 *
 * Each per-profile module exports a pure `validate*` function returning a
 * `ProfileValidationResult` AND an adapter `*Profile` matching the universal
 * `ProfileValidator` signature from `@dekimuhq/anchors-envelope`.
 */

import type { ApurProfile } from "./body.ts";

/**
 * Result of a pure profile validator. Errors are stable machine-readable
 * dot-separated codes prefixed with the profile id.
 */
export interface ProfileValidationResult {
  errors: string[];
}

/**
 * Discriminator over the 4 v1 profile ids. Re-exported from the verifier so
 * downstream packages can pin the ID set without importing both packages.
 */
export type { ApurProfile };
