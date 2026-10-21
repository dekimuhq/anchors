/**
 * Shared types for ASR v1 profile validators (spec §5).
 *
 * Each per-profile module exports a pure `validate*` function returning a
 * `ProfileValidationResult` AND an adapter `*ProfileValidator` matching the
 * universal `ProfileValidator` signature from `@dekimuhq/anchors-envelope`.
 *
 * Pure validators are side-effect-free and import-cycle-free; they take a
 * typed `AsrBody` (re-exported from `./body-types.ts` as a type-only
 * import to keep `asr-profiles` runtime-independent of `asr-verifier`).
 *
 * Unlike ANR/ABR (where `profile` is a body field), ASR carries the active
 * profile at the verify-call level (`verifyReceipt({ profile })`) — there is
 * no `body.profile` to cross-check. Dispatch is registry-keyed, so each
 * validator runs only when its profile id was selected by the caller.
 */

import type { AsrProfile } from "./body-types.ts";

/**
 * Result of a pure profile validator. Errors are stable machine-readable
 * dot-separated codes prefixed with the profile id (e.g.
 * `subject_rights.art17.erasure_request.arr_receipt_id.missing`).
 */
export interface ProfileValidationResult {
  errors: string[];
}

/**
 * Verifier-derived context surface available to ASR profile validators.
 *
 * Mirrors the relevant subset of `ProfileValidatorCtx` from
 * `@dekimuhq/anchors-envelope`. Declared locally so pure validators do not
 * pull the envelope package into their type surface — adapter wrappers
 * marshal between the two.
 */
export interface AsrProfileCtx {
  /** TSA verification reason (e.g. `"tsa_verified"`, `"tsa_absent"`). */
  tsa_state?: string;
  /** True iff the TSA was matched against a trust-list anchor (e.g. EUTL). */
  tsa_listed?: boolean;
  /** TSA policy OID parsed from the TSTInfo, if available. */
  tsa_policy_oid?: string;
}

/**
 * Discriminator over the 6 v1 profile ids. Re-exported from `./body-types.ts` (which now owns the leaf) so
 * downstream packages can pin the ID set without importing the verifier.
 */
export type { AsrProfile };
