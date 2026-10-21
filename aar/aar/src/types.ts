/**
 * AAR v1 types — spec §3 + §4.
 *
 * Claim type: ar.attestation.v1
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/aar
 */

import type { AarClaimType, AarEventType, AarProfile, AarServiceType, AarSignatureFormat, AarRevocationReason, AarIssuanceBody, AarRevocationBody, AarBody } from "@dekimuhq/aar-profiles";
export type { AarClaimType, AarEventType, AarProfile, AarServiceType, AarSignatureFormat, AarRevocationReason, AarIssuanceBody, AarRevocationBody, AarBody };

// ── Chain walker types (spec §7) ───────────────────────────────────────────────

export interface AarChainReceipt {
  id: string;
  iss: string;
  iat: string;
  prev: string | null;
  subject: string | null;
  body: AarBody;
}

export interface AarChainWalkResult {
  ok: boolean;
  hard_invalid_reasons: string[];
  warnings: string[];
}

// ── Depth-limit constants ──────────────────────────────────────────────────────

export const AAR_DEFAULT_DEPTH_LIMIT = 16;
export const AAR_DEPTH_LIMIT_MIN = 2;
export const AAR_DEPTH_LIMIT_MAX = 64;
