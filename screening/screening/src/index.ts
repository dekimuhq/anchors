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

const SKEW_MS = 5 * 60 * 1000;

function bindingOk(obj: Record<string, unknown>): boolean {
  try {
    const m = (obj.body as { matcher?: unknown } | undefined)?.matcher;
    return m !== undefined && obj.policy_hash === matcherPolicyHash(m as Parameters<typeof matcherPolicyHash>[0]);
  } catch {
    return false;
  }
}

/**
 * v=2 dispatch plus the AScR rules the envelope pipeline cannot see. Any failure
 * flips `signature_valid` to false with a spec §6 reason, so callers that only
 * read `signature_valid` can never accept a receipt that breaks them:
 *   - `screening.policy_hash.mismatch` — envelope `policy_hash` must equal the hash of `body.matcher`
 *   - `screening.prev.not_null`        — `prev` MUST be null (a chain would link one party's screens)
 *   - `screening.kind.not_decision`    — `kind` MUST be "decision"
 *   - `screening.screened_at.after_iat` — a screen cannot postdate the receipt (5 min skew)
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
  const bound = bindingOk(obj);
  let reason: string | undefined;
  if (!bound) reason = "screening.policy_hash.mismatch";
  else if (obj.prev !== null) reason = "screening.prev.not_null";
  else if (obj.kind !== "decision") reason = "screening.kind.not_decision";
  else {
    const sa = Date.parse(String((obj.body as { screened_at?: unknown } | undefined)?.screened_at));
    const iat = Date.parse(String(obj.iat));
    if (!Number.isNaN(sa) && !Number.isNaN(iat) && sa > iat + SKEW_MS) reason = "screening.screened_at.after_iat";
  }
  const out = { ...res, policy_binding: bound ? ("ok" as const) : ("mismatch" as const) };
  return reason === undefined ? out : { ...out, signature_valid: false, reason };
}
