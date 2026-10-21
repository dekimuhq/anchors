/**
 * Universal profile-validator types — Phase E Task E.2.
 *
 * A family verifier may accept an opt-in list of profile validators that
 * inspect the envelope + body after envelope signature + policy + status
 * checks have completed. Results are surfaced as `profile_state` on the
 * verifier result and are advisory only — a failing profile validator
 * MUST NOT poison `signature_valid` (mirrors TSA / status invariants).
 */

import type { Envelope } from "../envelope-types.ts";

/**
 * Verifier-context passed to profile validators. Subset of EnvelopeVerifyResult
 * sufficient for current profiles. Extensible — add fields here when new
 * profiles need additional verifier-derived inputs.
 */
export interface ProfileValidatorCtx {
  /** TsaReason value (kept as `string` for cross-package flexibility). */
  tsa_state?: string;
  tsa_listed?: boolean;
  tsa_policy_oid?: string;
}

/**
 * Result entry per validated profile. Advisory: an ok=false entry does NOT
 * poison signature_valid on the verifier result.
 */
export interface ProfileStateEntry {
  profile_id: string;
  ok: boolean;
  reason?: string;
}

/**
 * Universal profile-validator signature. Each adapter wraps a
 * profile-specific receipt/ctx-shaped validator and returns a uniform
 * ProfileStateEntry.
 */
export type ProfileValidator = (
  envelope: Envelope,
  body: unknown,
  ctx: ProfileValidatorCtx,
) => ProfileStateEntry;
