/**
 * esig.accept@qes — eIDAS QES acceptance profile mandate enforcement.
 * Phase D Task 21.
 *
 * This profile requires a QES-grade timestamp: the TSA must be EUTL-listed and
 * must operate under the ETSI EN 319 421 BTSP policy OID asserted by qualified
 * EU TSAs in TSTInfo.policy.
 */

import type { TsaBlock } from "@dekimuhq/anchors-envelope";
import type { TsaReason } from "@dekimuhq/anchors-envelope/tsa";
import type { ProfileDescriptor } from "./types.ts";

/**
 * Descriptor for the esig.accept@qes sub-profile.
 *
 * Policy OID "0.4.0.2023.1.1" is the ETSI EN 319 421 BTSP policy OID — the
 * identifier qualified EU TSAs assert in TSTInfo.policy. Confirmed in an
 * internal legal review (not published)
 * (supersedes the pre-Phase-E placeholder 0.4.0.19422.1.1, which lived under
 * the EN 319 422 protocol arc, not a policy arc).
 */
export const ESIG_ACCEPT_QES_DESCRIPTOR: ProfileDescriptor = {
  requires_tsa: true,
  requires_tsa_listed: true,
  requires_tsa_policy_oid: "0.4.0.2023.1.1",
};

/** Receipt shape this profile operates on (subset sufficient for mandate check). */
export interface EsigAcceptQesReceipt {
  tsa: TsaBlock | null;
}

/** Caller-supplied verification context — output of the envelope verifier. */
export interface EsigAcceptQesCtx {
  tsa_state: TsaReason;
  tsa_listed: boolean;
  tsa_policy_oid?: string;
}

/**
 * Validate that a receipt meets the esig.accept@qes mandate.
 *
 * Returns `{ ok: true }` only when:
 *   - a TSA block is present,
 *   - the TSA was successfully verified (`tsa_state === "tsa_verified"`),
 *   - the TSA is EUTL-listed (`ctx.tsa_listed === true`), and
 *   - the TSA policy OID matches the descriptor.
 */
export function validateEsigAcceptQes(
  receipt: EsigAcceptQesReceipt,
  ctx: EsigAcceptQesCtx,
): { ok: boolean; reason?: string } {
  if (!receipt.tsa) {
    return { ok: false, reason: "tsa_required_by_profile" };
  }
  if (ctx.tsa_state !== "tsa_verified") {
    return { ok: false, reason: `tsa_failed:${ctx.tsa_state}` };
  }
  if (!ctx.tsa_listed) {
    return { ok: false, reason: "tsa_listed_required_by_profile" };
  }
  if (ctx.tsa_policy_oid !== ESIG_ACCEPT_QES_DESCRIPTOR.requires_tsa_policy_oid) {
    return { ok: false, reason: "tsa_policy_oid_mismatch" };
  }
  return { ok: true };
}
