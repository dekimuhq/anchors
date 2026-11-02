/**
 * AAR TSA mandate — FAMILY-CONSISTENCY §2.
 *
 * AAR TSA mandate is event+service_type keyed:
 *   - issuance + service_type=qts  → MANDATORY (QTS issuance IS the timestamp)
 *   - issuance + other service types → RECOMMENDED
 *   - revocation → RECOMMENDED
 */

import type { AarBody } from "./types.ts";

export type TsaMandateLevel = "MANDATORY" | "RECOMMENDED" | "OPTIONAL";

export function tsaMandateLevel(body: AarBody): TsaMandateLevel {
  if (body.event_type === "issuance" && body.service_type === "qts") {
    return "MANDATORY";
  }
  return "RECOMMENDED";
}

export interface AarTsaMandateTarget {
  signature_valid: boolean;
  reason?: string;
  tsa_state?: string;
}

/**
 * Apply the event+service_type mandate to a verify result. Mutates `target`.
 *
 * - `MANDATORY` (issuance + qts) + any `tsa_state` other than
 *     `"tsa_verified"` → `signature_valid: false`. When no block was present
 *     (`"tsa_absent"` / undefined) → `reason: "tsa_required"`, `tsa_state:
 *     "tsa_required"`. A present-but-unverified block → `reason:
 *     "tsa_unverified"` and `tsa_state` keeps its real TSA reason (e.g.
 *     `"tsa_malformed"`). Fails closed because `tsa` is not
 *     signature-covered — anyone can attach a junk block to a genuine
 *     receipt. No-op when `signature_valid` is already false.
 * - `RECOMMENDED` + `tsa_state === "tsa_absent"` →
 *     `tsa_state: "tsa_recommended"` (warning only; signature not poisoned).
 *     Any other `tsa_state` is left untouched.
 */
export function applyAarTsaMandate(
  target: AarTsaMandateTarget,
  body: AarBody,
): void {
  const level = tsaMandateLevel(body);
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
  target.tsa_state = "tsa_recommended";
}
