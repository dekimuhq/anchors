export * from "./types.ts";

// -- Family manifest ----------------------------------------------------------

export { atrFamily } from "./family.ts";

// -- v=2 envelope types (re-exported from factory) ----------------------------

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// -- Body verifier + chain walkers --------------------------------------------

export * from "./verify-single.ts";
export * from "./chain.ts";

// -- TSA mandate matrix -------------------------------------------------------

export * from "./tsa-mandate.ts";

// -- Subject-presence rule (FAMILY-CONSISTENCY S3) ----------------------------

export * from "./subject-presence.ts";

// -- Composition surface ------------------------------------------------------

export { composeAtr } from "./compose.ts";

// -- v=2 envelope dispatch ----------------------------------------------------

import { atrFamily } from "./family.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";

type VerifyReceiptResult =
  | FamilyVerifyResult
  | { envelope_version: "unknown"; signature_valid: boolean; reason?: string };

/**
 * Top-level receipt verifier for ATR.
 *
 * ATR is v=2 only -- there is no v=1 legacy path. Dispatches as follows:
 *
 * - `v === 2`          -> `atrFamily.verifyReceipt`
 * - any other value    -> fail-closed with `"unsupported_envelope_version"`
 * - non-object input   -> fail-closed with `"schema_invalid"`
 */
export async function verifyReceipt(
  receipt: unknown,
  opts?: Partial<FamilyVerifyOptions>,
): Promise<VerifyReceiptResult> {
  if (typeof receipt !== "object" || receipt === null) {
    return { envelope_version: "unknown", signature_valid: false, reason: "schema_invalid" };
  }
  const obj = receipt as Record<string, unknown>;
  if (obj.v === 2) {
    return atrFamily.verifyReceipt(obj, {
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
