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

/**
 * Top-level receipt verifier for ABR.
 *
 * ABR is v=2 only — there is no v=1 legacy path. Dispatches as follows:
 *
 * - `v === 2`          -> `abrFamily.verifyReceipt`
 * - any other value    -> fail-closed with `"unsupported_envelope_version"`
 * - non-object input   -> fail-closed with `"schema_invalid"`
 *
 * ABR's event-keyed TSA mandate (`breach.detected` MANDATORY, D10-ABR-2 /
 * 72-hour clock) is `abrFamily`'s `body_tsa_mandate`, applied inside
 * `abrFamily.verifyReceipt` — so direct manifest callers and the CLI get it
 * too, not only this wrapper.
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
    return abrFamily.verifyReceipt(obj, {
      ...opts,
      resolveKey: opts?.resolveKey ?? (() => undefined),
    } as FamilyVerifyOptions);
  }
  return {
    envelope_version: "unknown",
    signature_valid: false,
    reason: "unsupported_envelope_version",
  } as unknown as FamilyVerifyResult;
}
