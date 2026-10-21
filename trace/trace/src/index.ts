export type {
  AgTRBody, AgTRCaveatsConsumed,
  TraceProfile, TraceClaimType, TraceOutcome, TraceStage, TraceStageStatus,
} from "./types.ts";
export { verifyTraceBody, type VerifyBodyResult } from "./verify-single.ts";
export { traceFamily } from "./family.ts";
export { traceBodyValidator } from "./body-validator.ts";

// ── v2 span-tree public surface ───────────────────────────────────────────────

export { verifyTraceTreeBody } from "./verify-tree.ts";
export type { AgTRTreeBody, Span, SpanStatus } from "./types.ts";
export { mintTraceV2, type MintTraceV2Input } from "./issue/mint-v2.ts";
export { buildSpansRoot, type SpanSaltSource } from "./spans-root.ts";

// ── v=2 envelope types (re-exported from factory) ────────────────────────────

export type {
  FamilyVerifyResult as EnvelopeVerifyResult,
  FamilyVerifyOptions as EnvelopeVerifyOptions,
} from "@dekimuhq/anchors-envelope";

// ── v=2 envelope dispatch ─────────────────────────────────────────────────────

import { traceFamily } from "./family.ts";
import type {
  FamilyVerifyResult,
  FamilyVerifyOptions,
} from "@dekimuhq/anchors-envelope";

export async function verifyReceipt(
  receipt: unknown,
  opts?: Partial<FamilyVerifyOptions>
): Promise<
  | FamilyVerifyResult
  | { envelope_version: "unknown"; signature_valid: false; reason: string }
> {
  if (typeof receipt !== "object" || receipt === null) {
    return {
      envelope_version: "unknown",
      signature_valid: false,
      reason: "schema_invalid",
    };
  }
  const obj = receipt as Record<string, unknown>;
  if (obj.v === 2) {
    return traceFamily.verifyReceipt(obj, {
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
