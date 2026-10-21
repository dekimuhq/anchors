export type {
  APIIRBody, APIIRClaimType, RedactionProfile,
  RedactionCategory, RedactionCounts,
} from "./types.ts";
export { verifyRedactionBody, type VerifyBodyResult } from "./verify-single.ts";
export { redactionFamily } from "./family.ts";
export { redactionBodyValidator } from "./body-validator.ts";
export { buildRedactionBody, type BuildRedactionBodyInput } from "./build-body.ts";

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

import { redactionFamily } from "./family.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";

export async function verifyReceipt(
  receipt: unknown,
  opts?: Partial<FamilyVerifyOptions>,
): Promise<
  | FamilyVerifyResult
  | { envelope_version: "unknown"; signature_valid: false; reason: string }
> {
  if (typeof receipt !== "object" || receipt === null) {
    return { envelope_version: "unknown", signature_valid: false, reason: "schema_invalid" };
  }
  const obj = receipt as Record<string, unknown>;
  if (obj.v === 2) {
    return redactionFamily.verifyReceipt(obj, {
      ...opts,
      resolveKey: opts?.resolveKey ?? (() => undefined),
    } as FamilyVerifyOptions);
  }
  return { envelope_version: "unknown", signature_valid: false, reason: "unsupported_envelope_version" };
}
