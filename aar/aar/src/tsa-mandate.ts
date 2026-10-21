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

export function applyAarTsaMandate(
  target: AarTsaMandateTarget,
  body: AarBody,
): void {
  const level = tsaMandateLevel(body);
  if (level === "OPTIONAL") return;
  if (target.tsa_state !== "tsa_absent") return;
  if (level === "MANDATORY") {
    target.signature_valid = false;
    target.reason = "tsa_required";
    target.tsa_state = "tsa_required";
    return;
  }
  target.tsa_state = "tsa_recommended";
}
