export * from "./types.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── §C per-event body verifier ────────────────────────────────────────────────

export * from "./verify-single.ts";

// ── §C envelope-`prev` chain walker ───────────────────────────────────────────

export * from "./chain.ts";

// ── §D per-event TSA mandate matrix ───────────────────────────────────────────

export * from "./tsa-mandate.ts";

// ── §E per-event subject-presence rule ────────────────────────────────────────

export * from "./subject-presence.ts";

// ── §G cross-family composition surface ───────────────────────────────────────

export * from "./composition.ts";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

export { abrFamily } from "./family.ts";
import { abrFamily } from "./family.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";
import { applyAbrTsaMandate } from "./tsa-mandate.ts";
import type { AbrBody } from "./types.ts";

/**
 * Top-level receipt verifier for ABR.
 *
 * ABR is v=2 only — there is no v=1 legacy path. Dispatches as follows:
 *
 * - `v === 2`          -> `abrFamily.verifyReceipt`
 * - any other value    -> fail-closed with `"unsupported_envelope_version"`
 * - non-object input   -> fail-closed with `"schema_invalid"`
 *
 * Post-processing: re-applies the per-event TSA mandate matrix
 * (`applyAbrTsaMandate`) because ABR's mandate is event-keyed
 * (`body.event_type`), not profile-keyed. The factory only enforces
 * profile-keyed MANDATORY; ABR's `breach.detected` MANDATORY (D10-ABR-2
 * / 72-hour clock) requires this post-step.
 */
export async function verifyReceipt(
  receipt: unknown,
  opts?: Partial<FamilyVerifyOptions>,
): Promise<FamilyVerifyResult> {
  if (typeof receipt !== "object" || receipt === null) {
    return { envelope_version: "unknown", signature_valid: false, reason: "schema_invalid" } as unknown as FamilyVerifyResult;
  }
  const obj = receipt as Record<string, unknown>;
  if (obj.v === 2) {
    const out = await abrFamily.verifyReceipt(obj, {
      ...opts,
      resolveKey: opts?.resolveKey ?? (() => undefined),
    } as FamilyVerifyOptions);

    // Re-apply per-event TSA mandate (event-keyed, not profile-keyed).
    // breach.detected + tsa_absent -> tsa_required (poisons sig)
    // other events + tsa_absent -> tsa_recommended (advisory only)
    const r = out as unknown as Record<string, unknown>;
    if (r.signature_valid && r.tsa_state === "tsa_absent") {
      const body = (obj as { body?: unknown }).body;
      if (body && typeof body === "object") {
        applyAbrTsaMandate(r as { signature_valid: boolean; reason?: string; tsa_state?: string }, body as AbrBody);
      }
    }

    return out;
  }
  return {
    envelope_version: "unknown",
    signature_valid: false,
    reason: "unsupported_envelope_version",
  } as unknown as FamilyVerifyResult;
}
