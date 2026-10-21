/**
 * Per-profile TSA mandate matrix for ANR.
 *
 * Authoritative source: `meta/FAMILY-CONSISTENCY.md §2` —
 *   ANR | `notice.aiact.art50_transparency` profile | MANDATORY |
 *       AI Act evidence stricter than baseline GDPR transparency
 *   ANR | other profiles                            | RECOMMENDED |
 *       Notice presentation deadlines
 *
 * Unlike ALR (which keys mandate on `body.event_type`), ANR keys on
 * `body.profile`: every ANR event type can carry any of the 5 v1 profiles
 * and the regulatory weight rides on the profile, not the lifecycle step.
 *
 * The mandate runs AFTER `tsa` dispatch in `envelope-v2.ts`. Real TSA
 * failure reasons (e.g. `tsa_imprint_mismatch`) win over the matrix.
 */

import type { AnrBody, AnrProfile } from "./types.ts";

export type TsaMandateLevel = "MANDATORY" | "RECOMMENDED" | "OPTIONAL";

/**
 * Per-profile mandate level. Five rows — one per v1 ANR profile.
 *
 * `notice.aiact.art50_transparency` is MANDATORY: AI Act Art. 50
 * disclosure evidence demands stronger time anchoring than baseline GDPR
 * transparency. All other profiles are RECOMMENDED — notice-presentation
 * deadlines are verifier-side checks where missing TSA downgrades
 * confidence but does not invalidate the receipt.
 */
export const ANR_TSA_MANDATE: Readonly<Record<AnrProfile, TsaMandateLevel>> = {
  "notice.art13.collected_direct": "RECOMMENDED",
  "notice.art14.collected_indirect": "RECOMMENDED",
  "notice.art26.joint_controller_essence": "RECOMMENDED",
  "notice.layered_transparency": "RECOMMENDED",
  "notice.aiact.art50_transparency": "MANDATORY",
};

/** Look up the mandate level for an ANR profile. Returns `undefined` for unknown profiles. */
export function tsaMandateLevel(profile: AnrProfile): TsaMandateLevel {
  return ANR_TSA_MANDATE[profile];
}

/**
 * Surface used by `applyAnrTsaMandate`. Matches the relevant subset of
 * `EnvelopeVerifyResult` — declared locally so the mandate module does not
 * import `envelope-v2.ts` (avoids a circular dependency).
 */
export interface AnrTsaMandateTarget {
  signature_valid: boolean;
  reason?: string;
  tsa_state?: string;
}

/**
 * Apply the per-profile mandate to a verify result. Mutates `target`.
 *
 * - `MANDATORY` + `tsa_state === "tsa_absent"` →
 *     `signature_valid: false`, `reason: "tsa_required"`,
 *     `tsa_state: "tsa_required"`.
 * - `RECOMMENDED` + `tsa_state === "tsa_absent"` →
 *     `tsa_state: "tsa_recommended"` (warning only; signature not poisoned).
 * - `OPTIONAL` → no-op. ANR v1 has no OPTIONAL profiles, but the branch is
 *   kept for forward-compatibility with the family-uniform mandate shape.
 *
 * When `target.tsa_state` is anything other than `"tsa_absent"` (e.g. a real
 * TSA reason like `"tsa_imprint_mismatch"`), mandate enforcement is a no-op —
 * the TSA dispatch result wins over the mandate matrix.
 *
 * Defensive: an unknown profile value short-circuits to no-op. The §C body
 * verifier and §F profile-validator dispatch are the authoritative gates for
 * profile validity; the mandate module silently declines to upgrade unknown
 * inputs rather than mis-flag them.
 */
export function applyAnrTsaMandate(
  target: AnrTsaMandateTarget,
  body: AnrBody,
): void {
  const level = ANR_TSA_MANDATE[body.profile];
  if (level === undefined) return;
  if (level === "OPTIONAL") return;
  if (target.tsa_state !== "tsa_absent") return;
  if (level === "MANDATORY") {
    target.signature_valid = false;
    target.reason = "tsa_required";
    target.tsa_state = "tsa_required";
    return;
  }
  // RECOMMENDED
  target.tsa_state = "tsa_recommended";
}
