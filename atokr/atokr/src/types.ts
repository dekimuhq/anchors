/**
 * ATokR v1 types — spec §3 + §4.
 *
 * Claim type: ar.tokenization.v1
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/atokr
 *
 * The body-shape types (`AtokrBody` and its four variants, `AtokrProfile`, the
 * claim/event-type and closed sub-field enums) are defined canonically in
 * `@dekimuhq/atokr-profiles` (`./body.ts` there) and re-exported here. They were
 * relocated so the profile validators can import the body shape without a
 * profiles→verifier import cycle (the verifier imports profile *values* in
 * `family.ts`). `@dekimuhq/atokr` re-exports every body symbol, so its
 * public type API is unchanged for downstream consumers.
 *
 * Only the chain-walker depth-limit constants — verifier-internal values, not
 * part of the body shape — remain defined in this package.
 */

import type { AtokrClaimType, AtokrEventType, AtokrProfile, AtokrFormatClass, AtokrPciEnvironment, AtokrAttributeCategory, AtokrDataUseCategory, AtokrScope, AtokrIssuedBody, AtokrRedeemedBody, AtokrRevokedBody, AtokrRotatedBody, AtokrBody } from "@dekimuhq/atokr-profiles";
export type { AtokrClaimType, AtokrEventType, AtokrProfile, AtokrFormatClass, AtokrPciEnvironment, AtokrAttributeCategory, AtokrDataUseCategory, AtokrScope, AtokrIssuedBody, AtokrRedeemedBody, AtokrRevokedBody, AtokrRotatedBody, AtokrBody };

// ── Chain walker types (spec §6) ───────────────────────────────────────────────

export interface AtokrChainReceipt {
  id: string;
  iss: string;
  iat: string;
  prev: string | null;
  subject: string | null;
  body: AtokrBody;
}

export interface AtokrChainWalkResult {
  ok: boolean;
  hard_invalid_reasons: string[];
  warnings: string[];
}

// ── Depth-limit constants ──────────────────────────────────────────────────────

/** Default cap on the number of envelope-`prev` hops the walker traverses. */
export const ATOKR_DEFAULT_DEPTH_LIMIT = 256;

/** Floor for the depth-limit option; values below this are clamped up. */
export const ATOKR_DEPTH_LIMIT_MIN = 32;

/** Ceiling for the depth-limit option; values above this are clamped down. */
export const ATOKR_DEPTH_LIMIT_MAX = 1024;
