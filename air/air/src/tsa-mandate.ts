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
 * The mandate runs AFTER `tsa` dispatch in `envelope-v2.ts`. Real TSA
 * failure reasons (e.g. `tsa_imprint_mismatch`) win over the matrix.
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
 * - `MANDATORY` + `tsa_state === "tsa_absent"` →
 *     `signature_valid: false`, `reason: "tsa_required"`,
 *     `tsa_state: "tsa_required"`. AIR v1 has no MANDATORY event; the branch
 *     is kept for forward-compatibility with the family-uniform mandate shape.
 * - `RECOMMENDED` + `tsa_state === "tsa_absent"` →
 *     `tsa_state: "tsa_recommended"` (warning only; signature not poisoned).
 * - `OPTIONAL` → no-op.
 *
 * When `target.tsa_state` is anything other than `"tsa_absent"` (e.g. a real
 * TSA reason like `"tsa_imprint_mismatch"`), mandate enforcement is a no-op —
 * the TSA dispatch result wins over the mandate matrix.
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
