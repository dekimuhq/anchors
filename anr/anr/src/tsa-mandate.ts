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
 * The mandate runs AFTER the shared pipeline's `tsa` dispatch (as a post-step
 * in this package's top-level `verifyReceipt`). A MANDATORY level fails
 * closed: absent → `reason: "tsa_required"`; present but not `tsa_verified`
 * (e.g. `tsa_imprint_mismatch`) → `reason: "tsa_unverified"` with the real
 * TSA reason kept in `tsa_state`. For RECOMMENDED / OPTIONAL a real TSA
 * failure reason is surfaced as-is and never poisons the signature.
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
 * - `MANDATORY` + any `tsa_state` other than `"tsa_verified"` →
 *     `signature_valid: false`. When no block was present (`"tsa_absent"` /
 *     undefined) → `reason: "tsa_required"`, `tsa_state: "tsa_required"`.
 *     A present-but-unverified block → `reason: "tsa_unverified"` and
 *     `tsa_state` keeps its real TSA reason (e.g. `"tsa_malformed"`). Fails closed because `tsa` is not
 *     signature-covered — anyone can attach a junk block to a genuine
 *     receipt. No-op when `signature_valid` is already false.
 * - `RECOMMENDED` + `tsa_state === "tsa_absent"` →
 *     `tsa_state: "tsa_recommended"` (warning only; signature not poisoned).
 * - `OPTIONAL` → no-op. ANR v1 has no OPTIONAL profiles, but the branch is
 *   kept for forward-compatibility with the family-uniform mandate shape.
 *
 * For `RECOMMENDED`, a `tsa_state` other than `"tsa_absent"` (e.g. a real
 * TSA reason like `"tsa_imprint_mismatch"`) is left untouched — the TSA
 * dispatch result is surfaced as-is and the signature is not poisoned.
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
  if (level === "MANDATORY") {
    // Fail closed: `tsa` is outside the signature, so only a verified token
    // satisfies the mandate. An earlier failure keeps its own reason.
    if (!target.signature_valid) return;
    if (target.tsa_state === "tsa_verified") return;
    const absent = target.tsa_state === undefined || target.tsa_state === "tsa_absent";
    target.signature_valid = false;
    // Absent → "tsa_required" (no timestamp). Present but unverified →
    // "tsa_unverified" (timestamp not confirmed, e.g. a verifier that does
    // not trust the anchor); tsa_state keeps the real TSA reason.
    target.reason = absent ? "tsa_required" : "tsa_unverified";
    if (absent) target.tsa_state = "tsa_required";
    return;
  }
  if (target.tsa_state !== "tsa_absent") return;
  // RECOMMENDED
  target.tsa_state = "tsa_recommended";
}
