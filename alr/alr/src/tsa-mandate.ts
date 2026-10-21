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
 * - `MANDATORY` + `tsa_state === "tsa_absent"` →
 *     `signature_valid: false`, `reason: "tsa_required"`,
 *     `tsa_state: "tsa_required"`.
 * - `RECOMMENDED` + `tsa_state === "tsa_absent"` →
 *     `tsa_state: "tsa_recommended"` (warning only; signature not poisoned).
 * - `OPTIONAL` → no-op.
 *
 * When `target.tsa_state` is anything other than `"tsa_absent"` (e.g. a real
 * TSA reason like `"tsa_imprint_mismatch"`), mandate enforcement is also a
 * no-op — the TSA dispatch result wins over the mandate matrix.
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
