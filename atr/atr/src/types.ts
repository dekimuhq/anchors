/**
 * ATR v1 types — spec §3 + §4.
 *
 * Claim type: ar.transfer.v1
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/atr
 */

import type { AtrClaimType, AtrEventType, AtrProfile, AtrMechanismVersion, AtrAssessmentOutcome, AtrSuspensionTrigger, AtrSubjectCountBucket, AtrArrangementBody, AtrTransferBody, AtrTiaBody, AtrSuspensionBody, AtrBody } from "@dekimuhq/atr-profiles";
export type { AtrClaimType, AtrEventType, AtrProfile, AtrMechanismVersion, AtrAssessmentOutcome, AtrSuspensionTrigger, AtrSubjectCountBucket, AtrArrangementBody, AtrTransferBody, AtrTiaBody, AtrSuspensionBody, AtrBody };

// ── Chain walker types (spec §7) ───────────────────────────────────────────────

export interface AtrChainReceipt {
  id: string;
  iss: string;
  iat: string;
  prev: string | null;
  subject: string | null;
  profile: string;
  body: AtrBody;
}

export interface AtrTransferValidityResult {
  valid: boolean;
  reasons: string[];
}

export interface AtrChainWalkResult {
  ok: boolean;
  hard_invalid_reasons: string[];
  warnings: string[];
}

export const ATR_DEFAULT_DEPTH_LIMIT = 256;
export const ATR_DEPTH_LIMIT_MIN = 32;
export const ATR_DEPTH_LIMIT_MAX = 1024;
