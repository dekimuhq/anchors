export * from "./types.ts";

// ── Family manifest (defineFamily) ────────────────────────────────────────────

export * from "./family.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── §C body verifier ──────────────────────────────────────────────────────────

export * from "./verify-single.ts";

// ── §C.2 envelope-prev chain walker ───────────────────────────────────────────

export * from "./chain.ts";

// ── §D per-profile TSA mandate matrix ─────────────────────────────────────────

export * from "./tsa-mandate.ts";

// ── §E subject-presence rule (per-event split) ────────────────────────────────

export * from "./subject-presence.ts";

// ── §G ACR ↔ ANR composition + ALR translation provenance ─────────────────────

export * from "./composition.ts";

// ── Phase 4D per-receipt compose-warnings callback ────────────────────────────

export { composeAnr } from "./compose.ts";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

import { anrFamily } from "./family.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";

type VerifyReceiptResult =
  | FamilyVerifyResult
  | { envelope_version: "unknown"; signature_valid: boolean; reason?: string };

/**
 * Top-level receipt verifier for ANR.
 *
 * ANR is v=2 only — there is no v=1 legacy path. Dispatches as follows:
 *
 * - `v === 2`          → `anrFamily.verifyReceipt`
 * - any other value    → fail-closed with `"unsupported_envelope_version"`
 * - non-object input   → fail-closed with `"schema_invalid"`
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
    // The TSA mandate keyed on body.profile (art50 MANDATORY) is anrFamily's
    // `body_tsa_mandate`, applied inside anrFamily.verifyReceipt.
    return anrFamily.verifyReceipt(obj, {
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
