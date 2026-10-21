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
import { applyAirTsaMandate } from "./tsa-mandate.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";
import type { AirBody } from "./types.ts";

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
 * Post-processing: the per-event TSA mandate matrix (§D) re-applies
 * `applyAirTsaMandate` to upgrade `tsa_absent` → `tsa_recommended` on
 * the three deadline-bearing events. The factory's profile-keyed mandate
 * only enforces MANDATORY (none in AIR v1).
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
    const out = await airFamily.verifyReceipt(obj, {
      ...opts,
      resolveKey: opts?.resolveKey ?? (() => undefined),
    } as FamilyVerifyOptions);

    // Re-apply the per-event TSA mandate matrix (event-keyed). The factory
    // only enforces MANDATORY (profile-keyed; AIR has none), and never
    // surfaces RECOMMENDED. `applyAirTsaMandate` reads `body.event_type` and
    // upgrades `tsa_absent` to `tsa_recommended` on the three deadline-bearing
    // events.
    if (out.signature_valid && out.tsa_state === "tsa_absent") {
      const body = (obj as { body?: unknown }).body;
      if (body && typeof body === "object") {
        applyAirTsaMandate(out, body as AirBody);
      }
    }

    return out;
  }
  return {
    envelope_version: "unknown",
    signature_valid: false,
    reason: "unsupported_envelope_version",
  };
}
