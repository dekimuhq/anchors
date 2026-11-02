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
 *     `"tsa_verified"` → `signature_valid: false`, `reason: "tsa_required"`.
 *     When no block was present (`"tsa_absent"` / undefined) `tsa_state`
 *     becomes `"tsa_required"`; a present-but-unverified block keeps its real
 *     TSA reason (e.g. `"tsa_malformed"`). Fails closed because `tsa` is not
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
    target.signature_valid = false;
    target.reason = "tsa_required";
    // Keep a real TSA reason (e.g. "tsa_malformed") so callers see why;
    // only the no-block case is relabelled.
    if (target.tsa_state === undefined || target.tsa_state === "tsa_absent") {
      target.tsa_state = "tsa_required";
    }
    return;
  }
  if (target.tsa_state !== "tsa_absent") return;
  target.tsa_state = "tsa_recommended";
}
