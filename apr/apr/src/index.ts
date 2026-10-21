/**
 * Public API of `@dekimuhq/apr` (verifier at the root export).
 *
 * Conforms to `apr-spec` v1. See https://github.com/dekimuhq/anchors-spec/blob/main/apr/v1.md
 */

export { aprFamily } from "./family.ts";
export { verify } from "./verify.ts";
export { verifyClaim } from "./verify-claim.ts";
export { verifyAnchor } from "./verify-anchor.ts";
export { applyDisclosure, pseudonymise } from "./disclosure.ts";
export type { DisclosedAprBody } from "./disclosure.ts";
export { canonicalize } from "./canonicalize.ts";
export { computeMerkleRoot } from "./merkle.ts";
export { base64UrlDecode, base64UrlEncode } from "./base64url.ts";
export type {
  APRArtifactType,
  APRAgentKind,
  APRDisclosure,
  APRInputKind,
  APRInput,
  APRBody,
  APRClaim,
  DailyRoot,
  ClaimVerifyingKey,
  RootVerifyingKey,
  ClaimKeyResolver,
  RootKeyResolver,
  VerifyStatus,
  VerifyReason,
  VerifyResult,
  VerifyInput,
} from "./types.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

import { aprFamily } from "./family.ts";
import { verifyClaim } from "./verify-claim.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";
import type { APRClaim, ClaimKeyResolver } from "./types.ts";

interface VerifyReceiptOptions extends Partial<FamilyVerifyOptions> {
  v1Opts?: {
    claimKeyResolver: ClaimKeyResolver;
    now?: () => number;
  };
}

type VerifyReceiptResult =
  | FamilyVerifyResult
  | { envelope_version: 1 | "unknown"; signature_valid: boolean; reason?: string };

/**
 * Top-level receipt verifier. Dispatches to the v=1 legacy sig-only verifier or
 * the v=2 factory verifier based on the `v` field. Fail-closed on any unknown
 * envelope version or malformed input.
 *
 * Note: v=1 APR requires `opts.v1Opts.claimKeyResolver`. Without it the call
 * fails closed with reason "v1_requires_claim_key_resolver". For full APR
 * verification (claim + anchor + Merkle inclusion) call verify() directly.
 */
export async function verifyReceipt(
  receipt: unknown,
  opts?: VerifyReceiptOptions,
): Promise<VerifyReceiptResult> {
  if (typeof receipt !== "object" || receipt === null) {
    return { envelope_version: "unknown", signature_valid: false, reason: "schema_invalid" };
  }
  const obj = receipt as Record<string, unknown>;
  const v = obj.v;
  if (v === undefined || v === 1) {
    if (!opts?.v1Opts?.claimKeyResolver) {
      return {
        envelope_version: 1,
        signature_valid: false,
        reason: "v1_requires_claim_key_resolver",
      };
    }
    try {
      const now = (opts.v1Opts.now ?? (() => Math.floor(Date.now() / 1000)))();
      const claim = obj as unknown as APRClaim;
      const result = verifyClaim(claim, opts.v1Opts.claimKeyResolver, now);
      return { envelope_version: 1, signature_valid: result.ok };
    } catch {
      return { envelope_version: 1, signature_valid: false, reason: "v1_verify_threw" };
    }
  }
  if (v === 2) {
    const { v1Opts: _, ...rest } = opts ?? {};
    return aprFamily.verifyReceipt(obj, {
      ...rest,
      resolveKey: rest.resolveKey ?? (() => undefined),
    } as FamilyVerifyOptions);
  }
  return {
    envelope_version: "unknown",
    signature_valid: false,
    reason: "unsupported_envelope_version",
  };
}
