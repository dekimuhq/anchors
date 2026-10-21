/**
 * APuR v1 types — spec §4.
 *
 * Claim type: ar.purpose.v1
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/apur
 */

import type { ApurClaimType, ApurEventType, ApurProfile, ApurCompatConclusion, ApurUnbindingReason, ApurDataSubjectsClass, ApurBindingBody, ApurRepurposeBody, ApurUnbindingBody, ApurBody } from "@dekimuhq/apur-profiles";
export type { ApurClaimType, ApurEventType, ApurProfile, ApurCompatConclusion, ApurUnbindingReason, ApurDataSubjectsClass, ApurBindingBody, ApurRepurposeBody, ApurUnbindingBody, ApurBody };

// ── Chain walker types (spec §7) ────────────────────────────────────────────────

export interface ApurChainReceipt {
  id: string;
  iss: string;
  iat: string;
  prev: string | null;
  subject: string | null;
  body: ApurBody;
}

export interface ApurChainWalkResult {
  ok: boolean;
  hard_invalid_reasons: string[];
  warnings: string[];
}

// ── Depth-limit constants ──────────────────────────────────────────────────────

export const APUR_DEFAULT_DEPTH_LIMIT = 64;
export const APUR_DEPTH_LIMIT_MIN = 8;
export const APUR_DEPTH_LIMIT_MAX = 256;
