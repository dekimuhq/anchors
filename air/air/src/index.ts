export * from "./types.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── §C body verifier + chain walker ───────────────────────────────────────────

export { verifyAirBody, isAirProfile } from "./verify-single.ts";
export type { VerifyAirBodyResult } from "./verify-single.ts";

export { buildAirChainIndex, walkAirChain } from "./chain.ts";
export type {
  AirChainReceipt,
  AirChainIndex,
  AirChainWalkOptions,
  AirChainWalkResult,
} from "./chain.ts";

// ── §D per-event TSA mandate matrix ───────────────────────────────────────────

export {
  AIR_TSA_MANDATE,
  tsaMandateLevel,
  applyAirTsaMandate,
} from "./tsa-mandate.ts";
export type { TsaMandateLevel, AirTsaMandateTarget } from "./tsa-mandate.ts";

// ── §E per-event subject-presence rule ────────────────────────────────────────

export {
  checkAirSubjectPresence,
  applyAirSubjectPresence,
} from "./subject-presence.ts";
export type {
  SubjectPresenceReason,
  SubjectPresenceResult,
  AirSubjectPresenceTarget,
} from "./subject-presence.ts";

// ── Phase 4B family manifest (defineFamily factory) ───────────────────────────

export { airFamily } from "./family.ts";
export { airBodyValidator } from "./body-validator.ts";
export { composeAir } from "./compose.ts";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

import { airFamily } from "./family.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";

type VerifyReceiptResult =
  | FamilyVerifyResult
  | { envelope_version: "unknown"; signature_valid: boolean; reason?: string };

/**
 * Top-level receipt verifier for AIR.
 *
 * AIR is v=2 only — there is no v=1 legacy path. Dispatches as follows:
 *
 * - `v === 2`          → `airFamily.verifyReceipt`
 * - any other value    → fail-closed with `"unsupported_envelope_version"`
 * - non-object input   → fail-closed with `"schema_invalid"`
 *
 * The per-event TSA mandate matrix (§D — `tsa_absent` → `tsa_recommended`
 * on the three deadline-bearing events) is `airFamily`'s `body_tsa_mandate`,
 * applied inside `airFamily.verifyReceipt` on every verify path.
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
    return airFamily.verifyReceipt(obj, {
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
