export * from "./types.ts";
export * from "./family.ts";
export * from "./verify-single.ts";
export * from "./chain.ts";
export * from "./subject-presence.ts";
export * from "./tsa-mandate.ts";
export { composeAar } from "./compose.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

import { aarFamily } from "./family.ts";
import { applyAarTsaMandate } from "./tsa-mandate.ts";
import type { AarBody } from "./types.ts";
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
    const out = await aarFamily.verifyReceipt(obj, {
      ...opts,
      resolveKey: opts?.resolveKey ?? (() => undefined),
    } as FamilyVerifyOptions);

    // Re-apply per-event TSA mandate (event+service_type keyed, not profile-keyed).
    // issuance+qts + tsa_absent -> tsa_required (poisons sig); other events +
    // tsa_absent -> tsa_recommended (advisory). Mirrors ABR/AIR — the factory
    // only enforces profile-keyed MANDATORY, so this post-step carries AAR's
    // body-keyed rule (FAMILY-CONSISTENCY §2).
    const r = out as unknown as Record<string, unknown>;
    if (r.signature_valid && r.tsa_state === "tsa_absent") {
      const body = (obj as { body?: unknown }).body;
      if (body && typeof body === "object") {
        applyAarTsaMandate(r as { signature_valid: boolean; reason?: string; tsa_state?: string }, body as AarBody);
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
