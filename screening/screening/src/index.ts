export type {
  AScRBody, AScRProfile, ScreeningListBody, ScreeningList, ScreeningMatcher,
  ScreeningCandidate, ScreeningResult, ScreeningTrigger,
} from "./types.ts";
export { verifyScreeningBody, type VerifyBodyResult } from "./verify-single.ts";
export { screeningFamily } from "./family.ts";
export { screeningBodyValidator } from "./body-validator.ts";
export { matcherPolicyHash } from "./policy.ts";

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

import { screeningFamily } from "./family.ts";
import { matcherPolicyHash } from "./policy.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";

export type ScreeningVerifyResult =
  | (FamilyVerifyResult & { policy_binding: "ok" | "mismatch" })
  | { envelope_version: "unknown"; signature_valid: false; reason: string };

/**
 * v=2 dispatch plus the AScR-specific binding check: the envelope `policy_hash`
 * MUST equal the hash of `body.matcher` (spec §2.1, error screening.policy_hash.mismatch).
 */
export async function verifyReceipt(
  receipt: unknown,
  opts?: Partial<FamilyVerifyOptions>
): Promise<ScreeningVerifyResult> {
  if (typeof receipt !== "object" || receipt === null) {
    return { envelope_version: "unknown", signature_valid: false, reason: "schema_invalid" };
  }
  const obj = receipt as Record<string, unknown>;
  if (obj.v !== 2) {
    return { envelope_version: "unknown", signature_valid: false, reason: "unsupported_envelope_version" };
  }
  const res = await screeningFamily.verifyReceipt(obj, {
    ...opts,
    resolveKey: opts?.resolveKey ?? (() => undefined),
  } as FamilyVerifyOptions);
  const m = (obj.body as { matcher?: Parameters<typeof matcherPolicyHash>[0] } | undefined)?.matcher;
  const bound = m !== undefined && typeof m === "object" && m !== null && obj.policy_hash === matcherPolicyHash(m);
  return { ...res, policy_binding: bound ? "ok" : "mismatch" };
}
