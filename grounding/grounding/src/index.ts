export type {
  GroundingProfile, ScorerMethod, SupportLevel,
  GroundingSource, GroundingCitation, GroundingClaim, Scorer,
  AGrRCaveatsConsumed, GroundingRagBody, AGrRBody,
} from "./types.ts";
export { verifyGroundingBody, type VerifyBodyResult } from "./verify-single.ts";
export { groundingFamily } from "./family.ts";
export { groundingBodyValidator } from "./body-validator.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

import { groundingFamily } from "./family.ts";
import type {
  FamilyVerifyResult,
  FamilyVerifyOptions,
} from "@dekimuhq/anchors-envelope";

export async function verifyReceipt(
  receipt: unknown,
  opts?: Partial<FamilyVerifyOptions>
): Promise<
  | FamilyVerifyResult
  | { envelope_version: "unknown"; signature_valid: false; reason: string }
> {
  if (typeof receipt !== "object" || receipt === null) {
    return {
      envelope_version: "unknown",
      signature_valid: false,
      reason: "schema_invalid",
    };
  }
  const obj = receipt as Record<string, unknown>;
  if (obj.v === 2) {
    return groundingFamily.verifyReceipt(obj, {
      ...opts,
      resolveKey: opts?.resolveKey ?? (() => undefined),
    } as FamilyVerifyOptions);
  }
  return {
    envelope_version: "unknown",
    signature_valid: false,
    reason: "unsupported_envelope_version",
  };
}
