import type { AnyARRReceipt } from "./body-types.ts";
import type { TsaBlock } from "@dekimuhq/anchors-envelope";
import type { TsaReason } from "@dekimuhq/anchors-envelope/tsa";
import type { ProfileDescriptor } from "./types.ts";

export interface ProfileValidationResult {
  errors: string[];
}

const ALLOWED_KINDS = new Set(["ar.erasure.v1", "ar.anonymization.v1"]);

export function validateGdprArt17(r: AnyARRReceipt): ProfileValidationResult {
  const errors: string[] = [];

  if (r.kind === "ar.batch.v1") {
    errors.push("gdpr.art17.mode_a.required");
    return { errors };
  }

  if (!ALLOWED_KINDS.has(r.kind)) errors.push("gdpr.art17.kind.disallowed");

  const sdc = (r as Record<string, unknown>).subject_data_categories;
  if (!Array.isArray(sdc) || sdc.length === 0) {
    errors.push("gdpr.art17.subject_data_categories.required");
  }

  if (!(r as Record<string, unknown>).controller_contact_hash) {
    errors.push("gdpr.art17.controller_contact_hash.required");
  }

  return { errors };
}

// ── gdpr.art17.erasure-finalized sub-profile (Phase D Task 21) ────────────────

/**
 * Descriptor for the gdpr.art17.erasure-finalized sub-profile.
 *
 * Any verified TSA is acceptable (listed or not) — this profile does not
 * mandate EUTL listing, only that the timestamp was successfully verified.
 */
export const GDPR_ART17_ERASURE_FINALIZED: ProfileDescriptor = {
  requires_tsa: true,
  requires_tsa_listed: false, // any verified TSA acceptable (FreeTSA included)
};

/** Receipt shape this profile operates on (subset sufficient for mandate check). */
export interface ErasureFinalizedReceipt {
  /** ARR discriminator — must be "ar.erasure.v1" for this sub-profile. */
  kind: string;
  tsa: TsaBlock | null;
}

/** Caller-supplied verification context — output of the envelope verifier. */
export interface ErasureFinalizedCtx {
  tsa_state: TsaReason;
}

/**
 * Validate that a receipt meets the gdpr.art17.erasure-finalized mandate.
 *
 * Returns `{ ok: true }` only when:
 *   - the receipt kind is "ar.erasure.v1",
 *   - a TSA block is present, and
 *   - the TSA was successfully verified (`tsa_state === "tsa_verified"`).
 *
 * EUTL listing is NOT required by this profile — any verified TSA is accepted.
 */
export function validateGdprArt17ErasureFinalized(
  receipt: ErasureFinalizedReceipt,
  ctx: ErasureFinalizedCtx,
): { ok: boolean; reason?: string } {
  if (receipt.kind !== "ar.erasure.v1") {
    return { ok: false, reason: "claim_type_mismatch" };
  }
  if (!receipt.tsa) {
    return { ok: false, reason: "tsa_required_by_profile" };
  }
  if (ctx.tsa_state !== "tsa_verified") {
    return { ok: false, reason: `tsa_failed:${ctx.tsa_state}` };
  }
  return { ok: true };
}
