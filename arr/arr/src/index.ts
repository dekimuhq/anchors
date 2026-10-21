export * from "./types.ts";
export { arrFamily } from "./family.ts";
export * from "./crypto-reexports.ts";
export * from "./verify-single.ts";
export * from "./chain.ts";
export * from "./verify-batch.ts";
export * from "./disclose-batch.ts";
export * from "./trigger.ts";
export * from "./window.ts";
export * from "./tsa-mandate.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

import { arrFamily } from "./family.ts";
import { verifySingleReceipt, type VerifySingleOptions } from "./verify-single.ts";
import { applyArrTsaMandate, type ArrTsaMandateTarget } from "./tsa-mandate.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";
import type { ARRReceipt } from "./types.ts";

interface VerifyReceiptOptions extends Partial<FamilyVerifyOptions> {
  v1Opts?: VerifySingleOptions;
}

type VerifyReceiptResult =
  | FamilyVerifyResult
  | { envelope_version: 1 | "unknown"; signature_valid: boolean; reason?: string };

/**
 * Top-level receipt verifier. Dispatches to the v=1 legacy verifier or the
 * v=2 factory verifier based on the `v` field. Fail-closed on any unknown
 * envelope version or malformed input.
 *
 * Note: v=1 ARR receipts require `opts.v1Opts.anchorInclusionTime`. Without it
 * the call fails closed with reason "v1_requires_anchor_inclusion_time".
 */
export async function verifyReceipt(
  receipt: unknown,
  opts?: VerifyReceiptOptions,
): Promise<VerifyReceiptResult> {
  if (typeof receipt !== "object" || receipt === null) {
    return { envelope_version: "unknown", signature_valid: false, reason: "schema_invalid" };
  }
  const obj = receipt as Record<string, unknown>;
  const v = obj.v;
  if (v === undefined || v === 1) {
    if (!opts?.v1Opts?.anchorInclusionTime) {
      return {
        envelope_version: 1,
        signature_valid: false,
        reason: "v1_requires_anchor_inclusion_time",
      };
    }
    try {
      const result = verifySingleReceipt(obj as unknown as ARRReceipt, opts.v1Opts);
      return { envelope_version: 1, signature_valid: result.valid };
    } catch {
      return { envelope_version: 1, signature_valid: false, reason: "v1_verify_threw" };
    }
  }
  if (v === 2) {
    const { v1Opts: _, ...rest } = opts ?? {};
    const out = await arrFamily.verifyReceipt(obj, {
      ...rest,
      resolveKey: rest.resolveKey ?? (() => undefined),
    } as FamilyVerifyOptions);

    // Per-event TSA mandate (FAMILY-CONSISTENCY §2): ARR's MANDATORY case
    // (erasure-finalized profile) is profile-keyed and handled by the factory
    // above; every other ARR event is RECOMMENDED, so upgrade an otherwise-valid
    // tsa_absent result to tsa_recommended. Mirrors ABR/AIR.
    const r = out as unknown as Record<string, unknown>;
    if (r.signature_valid && r.tsa_state === "tsa_absent") {
      applyArrTsaMandate(r as unknown as ArrTsaMandateTarget);
    }
    return out;
  }
  return {
    envelope_version: "unknown",
    signature_valid: false,
    reason: "unsupported_envelope_version",
  };
}
