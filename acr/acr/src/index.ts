/**
 * `@dekimuhq/acr` — verifier for Anchored Consent Receipts (ACR) v1 (root export of the consolidated family package).
 */

export { acrFamily } from "./family.ts";
export { canonicalize, base64UrlEncode, base64UrlDecode } from "./canonicalize.ts";
export { commit, verifyCommitment, randomSalt } from "./commit.ts";

export type {
  AcrKind,
  AcrProfile,
  AcrAnchor,
  ACRReceipt,
  FieldDisclosure,
  DisclosureProof,
} from "./types.ts";

export { buildTree, inclusionProof, verifyInclusion } from "./merkle.ts";
export type { MerkleTree } from "./merkle.ts";

export { verifyReceiptSignature } from "./verify.ts";

export { hashReceipt, resolveChainState } from "./chain.ts";
export type { ChainStatus, ChainState } from "./chain.ts";

export { verifyDisclosureProof } from "./disclose.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

import { acrFamily } from "./family.ts";
import { verifyReceiptSignature } from "./verify.ts";
import type { FamilyVerifyResult, FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";
import type { ACRReceipt } from "./types.ts";

type VerifyReceiptResult =
  | FamilyVerifyResult
  | { envelope_version: 1 | "unknown"; signature_valid: boolean; reason?: string };

/**
 * Top-level receipt verifier. Dispatches to the v=1 legacy verifier or the
 * v=2 factory verifier based on the `v` field. Fail-closed on any unknown
 * envelope version or malformed input.
 */
export async function verifyReceipt(
  receipt: unknown,
  opts?: Partial<FamilyVerifyOptions>,
): Promise<VerifyReceiptResult> {
  if (typeof receipt !== "object" || receipt === null) {
    return { envelope_version: "unknown", signature_valid: false, reason: "schema_invalid" };
  }
  const obj = receipt as Record<string, unknown>;
  const v = obj.v;
  if (v === undefined || v === 1) {
    try {
      const ok = verifyReceiptSignature(obj as unknown as ACRReceipt);
      return { envelope_version: 1, signature_valid: ok };
    } catch {
      return { envelope_version: 1, signature_valid: false, reason: "v1_verify_threw" };
    }
  }
  if (v === 2) {
    return acrFamily.verifyReceipt(obj, {
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
