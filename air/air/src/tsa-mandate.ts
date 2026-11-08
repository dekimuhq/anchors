/**
 * Per-event TSA mandate matrix for AIR.
 *
 * Authoritative source: `meta/FAMILY-CONSISTENCY.md §2` —
 *   AIR | `body.event_type: dpia.completed`                    | RECOMMENDED
 *   AIR | `body.event_type: dpia.prior_consultation_initiated` | RECOMMENDED
 *   AIR | `body.event_type: dpia.prior_consultation_resolved`  | RECOMMENDED
 *   AIR | other events                                          | OPTIONAL
 *
 * AIR keys mandate on `body.event_type` (like ABR / ALR), not `body.profile`
 * (like ANR). The three RECOMMENDED events are the regulatory-clock-bearing
 * ones: §4.5 (DPIA artifact anchored — sequence vs `processing_start_at`),
 * §4.7 (Art. 36 prior-consultation submission), §4.8 (Art. 36 DPA-advice
 * resolution). The remaining eight events are OPTIONAL — they participate in
 * the lifecycle but don't bear an externally-imposed deadline.
 *
 * AIR has NO MANDATORY-TSA event in v1 — in contrast to ABR's
 * `breach.detected` (the 72-hour clock starts there). The audit-fix H7
 * principled rule (regulatory-clock-start ⇒ MANDATORY) intentionally lands
 * AIR's three deadline-checks at RECOMMENDED only; raising any to MANDATORY
 * would force every controller to operate a TSA before they can record a
 * DPIA, which the spec deliberately avoids until eIDAS QTS rollout is
 * universal.
 *
 * The mandate runs AFTER the shared pipeline's `tsa` dispatch (as a post-step
 * in this package's top-level `verifyReceipt`). A MANDATORY level fails
 * closed: absent → `reason: "tsa_required"`; present but not `tsa_verified`
 * (e.g. `tsa_imprint_mismatch`) → `reason: "tsa_unverified"` with the real
 * TSA reason kept in `tsa_state`. For RECOMMENDED / OPTIONAL a real TSA
 * failure reason is surfaced as-is and never poisons the signature.
 */

import type { AirBody, AirEventType } from "./types.ts";

export type TsaMandateLevel = "MANDATORY" | "RECOMMENDED" | "OPTIONAL";

/**
 * Per-event mandate level. Eleven rows — one per v1 AIR event type.
 *
 * Three RECOMMENDED rows match FAMILY-CONSISTENCY §2's principled
 * regulatory-clock rule (`dpia.completed`, `dpia.prior_consultation_initiated`,
 * `dpia.prior_consultation_resolved`). The other eight events are OPTIONAL —
 * a verifier-side missing TSA on those is acceptable.
 */
export const AIR_TSA_MANDATE: Readonly<Record<AirEventType, TsaMandateLevel>> = {
  "dpia.threshold_triggered": "OPTIONAL",
  "dpia.scope_locked": "OPTIONAL",
  "dpia.dpo_advised": "OPTIONAL",
  "dpia.stakeholders_consulted": "OPTIONAL",
  "dpia.completed": "RECOMMENDED",
  "dpia.reviewed": "OPTIONAL",
  "dpia.prior_consultation_initiated": "RECOMMENDED",
  "dpia.prior_consultation_resolved": "RECOMMENDED",
  "dpia.processing_authorised": "OPTIONAL",
  "dpia.processing_blocked": "OPTIONAL",
  "dpia.terminated": "OPTIONAL",
};

/** Look up the mandate level for an AIR event type. */
export function tsaMandateLevel(event_type: AirEventType): TsaMandateLevel {
  return AIR_TSA_MANDATE[event_type];
}

/**
 * Surface used by `applyAirTsaMandate`. Matches the relevant subset of
 * `EnvelopeVerifyResult` — declared locally so the mandate module does not
 * import `envelope-v2.ts` (avoids a circular dependency).
 */
export interface AirTsaMandateTarget {
  signature_valid: boolean;
  reason?: string;
  tsa_state?: string;
}

/**
 * Apply the per-event mandate to a verify result. Mutates `target`.
 *
 * - `MANDATORY` + any `tsa_state` other than `"tsa_verified"` →
 *     `signature_valid: false`. When no block was present (`"tsa_absent"` /
 *     undefined) → `reason: "tsa_required"`, `tsa_state: "tsa_required"`.
 *     A present-but-unverified block → `reason: "tsa_unverified"` and
 *     `tsa_state` keeps its real TSA reason (e.g. `"tsa_malformed"`). Fails closed because `tsa` is not
 *     signature-covered — anyone can attach a junk block to a genuine
 *     receipt. No-op when `signature_valid` is already false. AIR v1 has
 *     no MANDATORY event; the branch is kept for forward-compatibility with
 *     the family-uniform mandate shape.
 * - `RECOMMENDED` + `tsa_state === "tsa_absent"` →
 *     `tsa_state: "tsa_recommended"` (warning only; signature not poisoned).
 * - `OPTIONAL` → no-op.
 *
 * For `RECOMMENDED`, a `tsa_state` other than `"tsa_absent"` (e.g. a real
 * TSA reason like `"tsa_imprint_mismatch"`) is left untouched — the TSA
 * dispatch result is surfaced as-is and the signature is not poisoned.
 *
 * Defensive: an unknown event_type short-circuits to no-op. The §C body
 * verifier is the authoritative gate for event-type validity; the mandate
 * module silently declines to upgrade unknown inputs rather than mis-flag
 * them.
 */
export function applyAirTsaMandate(
  target: AirTsaMandateTarget,
  body: AirBody,
): void {
  const level = AIR_TSA_MANDATE[body.event_type];
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
