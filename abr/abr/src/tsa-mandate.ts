/**
 * Per-event TSA mandate matrix for ABR.
 *
 * Authoritative source: `meta/FAMILY-CONSISTENCY.md §2` —
 *   ABR | `body.event_type: detected` | MANDATORY  | The 72-hour clock starts here; no exception (spec D10-ABR-2)
 *   ABR | other events                | RECOMMENDED | All breach-lifecycle events are deadline-sensitive
 *
 * ABR keys mandate on `body.event_type` (like ALR), not `body.profile` (like
 * ANR). Every ABR profile applies the same lifecycle, and the regulatory
 * weight rides on the event — `breach.detected` triggers GDPR Art. 33's
 * 72-hour clock regardless of which profile the receipt carries.
 *
 * The mandate runs AFTER the shared pipeline's `tsa` dispatch (as a post-step
 * in this package's top-level `verifyReceipt`). A MANDATORY level fails
 * closed: absent → `reason: "tsa_required"`; present but not `tsa_verified`
 * (e.g. `tsa_imprint_mismatch`) → `reason: "tsa_unverified"` with the real
 * TSA reason kept in `tsa_state`. For RECOMMENDED / OPTIONAL a real TSA
 * failure reason is surfaced as-is and never poisons the signature.
 */

import type { AbrBody, AbrEventType } from "./types.ts";

export type TsaMandateLevel = "MANDATORY" | "RECOMMENDED" | "OPTIONAL";

/**
 * Per-event mandate level. Eight rows — one per v1 ABR event type.
 *
 * `breach.detected` is MANDATORY: spec D10-ABR-2 starts the GDPR Art. 33
 * 72-hour clock at this event and there is no exception. All other events
 * are RECOMMENDED — they are deadline-sensitive (Art. 34 notification,
 * containment attestation, closure) but a verifier-side missing TSA
 * downgrades confidence rather than invalidating the receipt.
 */
export const ABR_TSA_MANDATE: Readonly<Record<AbrEventType, TsaMandateLevel>> = {
  "breach.detected": "MANDATORY",
  "breach.assessed": "RECOMMENDED",
  "breach.dpa_notified": "RECOMMENDED",
  "breach.dpa_delayed": "RECOMMENDED",
  "breach.subject_notified": "RECOMMENDED",
  "breach.subject_notification_exempted": "RECOMMENDED",
  "breach.contained": "RECOMMENDED",
  "breach.closed": "RECOMMENDED",
};

/** Look up the mandate level for an ABR event type. */
export function tsaMandateLevel(event_type: AbrEventType): TsaMandateLevel {
  return ABR_TSA_MANDATE[event_type];
}

/**
 * Surface used by `applyAbrTsaMandate`. Matches the relevant subset of
 * `EnvelopeVerifyResult` — declared locally so the mandate module does not
 * import `envelope-v2.ts` (avoids a circular dependency).
 */
export interface AbrTsaMandateTarget {
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
 *     receipt. No-op when `signature_valid` is already false.
 * - `RECOMMENDED` + `tsa_state === "tsa_absent"` →
 *     `tsa_state: "tsa_recommended"` (warning only; signature not poisoned).
 * - `OPTIONAL` → no-op. ABR v1 has no OPTIONAL events, but the branch is
 *   kept for forward-compatibility with the family-uniform mandate shape.
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
export function applyAbrTsaMandate(
  target: AbrTsaMandateTarget,
  body: AbrBody,
): void {
  const level = ABR_TSA_MANDATE[body.event_type];
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
