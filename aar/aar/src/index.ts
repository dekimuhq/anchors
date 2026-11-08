export * from "./types.ts";
export * from "./family.ts";
export * from "./verify-single.ts";
export * from "./chain.ts";
export * from "./subject-presence.ts";
export * from "./tsa-mandate.ts";
export { composeAar } from "./compose.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

import { aarFamily } from "./family.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";

export async function verifyReceipt(
  receipt: unknown,
  opts?: Partial<FamilyVerifyOptions>,
): Promise<FamilyVerifyResult | { envelope_version: "unknown"; signature_valid: false; reason: string }> {
  if (typeof receipt !== "object" || receipt === null) {
    return { envelope_version: "unknown", signature_valid: false, reason: "schema_invalid" };
  }
  const obj = receipt as Record<string, unknown>;
  if (obj.v === 2) {
    // AAR's event+service_type keyed TSA mandate (FAMILY-CONSISTENCY §2) is
    // aarFamily's `body_tsa_mandate`, applied inside aarFamily.verifyReceipt.
    return aarFamily.verifyReceipt(obj, {
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
