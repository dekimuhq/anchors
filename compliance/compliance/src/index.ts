export type {
  ComplianceBundleBody, BundleRef, GapDecl, NotApplicableDecl, ControllerIdentity, ComplianceClaimType, VerifyBodyResult,
} from "./types.ts";
export { verifyComplianceBundleBody } from "./verify-single.ts";
export { complianceFamily } from "./family.ts";
export { complianceBodyValidator } from "./body-validator.ts";

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

import { complianceFamily } from "./family.ts";
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
    return complianceFamily.verifyReceipt(obj, {
      ...opts,
      resolveKey: opts?.resolveKey ?? (() => undefined),
    } as FamilyVerifyOptions);
  }
  return { envelope_version: "unknown", signature_valid: false, reason: "unsupported_envelope_version" };
}
