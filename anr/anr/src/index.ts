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
import { applyAnrTsaMandate } from "./tsa-mandate.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";
import type { AnrBody } from "./types.ts";

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
    const out = await anrFamily.verifyReceipt(obj, {
      ...opts,
      resolveKey: opts?.resolveKey ?? (() => undefined),
    } as FamilyVerifyOptions);

    // Re-apply per-profile TSA mandate (RECOMMENDED upgrade).
    // Factory only enforces MANDATORY; RECOMMENDED surfaces as advisory
    // tsa_state upgrade without poisoning signature_valid.
    const r = out as unknown as Record<string, unknown>;
    if (r.signature_valid && r.tsa_state === "tsa_absent") {
      const body = (obj as { body?: unknown }).body;
      if (body && typeof body === "object") {
        applyAnrTsaMandate(
          r as { signature_valid: boolean; reason?: string; tsa_state?: string },
          body as AnrBody,
        );
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
