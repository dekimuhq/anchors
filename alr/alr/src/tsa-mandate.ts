/**
 * Per-event TSA mandate matrix for ALR.
 *
 * Authoritative source: `meta/FAMILY-CONSISTENCY.md §2` —
 * `ALR | (any) | OPTIONAL | Lineage; no regulatory clock`.
 *
 * All four ALR event types are OPTIONAL at the verifier base level in v1.
 * The `aiact.art53.gpai-training` profile MAY internally upgrade TSA to
 * RECOMMENDED — that enforcement lives in `@dekimuhq/alr-profiles`, not
 * here, per spec §4.5 and the §D pattern in the 10-spec batch plan.
 *
 * `applyAlrTsaMandate` is kept as scaffolding so any v1.1 tightening lands
 * in this module — never in `envelope-v2.ts` — preserving the family-
 * uniform `tsa-mandate.ts` shape promised by the shared per-spec pattern.
 */

import type { AlrBody, AlrEventType } from "./types.ts";

export type TsaMandateLevel = "MANDATORY" | "RECOMMENDED" | "OPTIONAL";

/**
 * Per-event mandate level. All OPTIONAL for ALR v1 (no regulatory clock).
 */
export const ALR_TSA_MANDATE: Readonly<Record<AlrEventType, TsaMandateLevel>> = {
  derived_from: "OPTIONAL",
  forked_from: "OPTIONAL",
  superseded_by: "OPTIONAL",
  disclosed: "OPTIONAL",
};

/** Look up the mandate level for an ALR event type. */
export function tsaMandateLevel(event_type: AlrEventType): TsaMandateLevel {
  return ALR_TSA_MANDATE[event_type];
}

/**
 * Surface used by `applyAlrTsaMandate`. Matches the relevant subset of
 * `EnvelopeVerifyResult` — declared locally so the mandate module does not
 * import `envelope-v2.ts` (avoids a circular dependency).
 */
export interface AlrTsaMandateTarget {
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
 * - `OPTIONAL` → no-op.
 *
 * For `RECOMMENDED`, a `tsa_state` other than `"tsa_absent"` (e.g. a real
 * TSA reason like `"tsa_imprint_mismatch"`) is left untouched — the TSA
 * dispatch result is surfaced as-is and the signature is not poisoned.
 *
 * For ALR v1 every event_type maps to OPTIONAL, so this is currently a
 * no-op for every receipt. See module header for upgrade guidance.
 */
export function applyAlrTsaMandate(
  target: AlrTsaMandateTarget,
  body: AlrBody,
): void {
  const level = tsaMandateLevel(body.event_type);
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
