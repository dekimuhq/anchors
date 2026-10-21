export type {
  AQRBody, AQROutputBody, AQRReleaseBody, AQRCaveatsConsumed,
  AQRProfile, AQRClaimType, QualityScorer, QualityResult, QualityVerdict,
} from "./types.ts";
export { verifyQualityBody, type VerifyBodyResult } from "./verify-single.ts";
export { qualityFamily } from "./family.ts";
export { qualityBodyValidator } from "./body-validator.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

import { qualityFamily } from "./family.ts";
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
    return qualityFamily.verifyReceipt(obj, {
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
