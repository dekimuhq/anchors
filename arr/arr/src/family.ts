/**
 * ARR family manifest — Phase A.3 step 2 adoption of `defineFamily()`.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 *
 * ARR is the third family member (after the ALR canary at `a7ae33c` and the
 * APR step at Phase A.3 step 1) to consume `defineFamily()` from
 * `@dekimuhq/anchors-envelope`. Phase A.3 is non-breaking — the public API of
 * `@dekimuhq/arr` (verify + ./issue) stays
 * byte-equal. The manifest is wired in under the hood:
 *
 *   - `envelope-v2.ts` uses `arrFamily.isOwnedClaimType()` to gate the
 *     `wrong_protocol` reason in place of the hand-rolled `ARR_CLAIM_TYPE_SET`.
 *   - `arr-issuer-kit/mint-v2.ts` reads its per-event `claim_type` literals
 *     from `arrFamily.meta.claim_types` (six entries, including
 *     `ar.batch.v1`).
 *
 * ARR has six v=2 claim_types: `ar.erasure.v1`, `ar.expiry.v1`, `ar.hold.v1`,
 * `ar.anonymization.v1`, `ar.archive.v1`, `ar.batch.v1`. Note that the v=1
 * `ArrSingleKind` union additionally contains v=1-only internal kinds
 * (`arr.hold_extension.v1`, `arr.hold_release.v1`, `arr.pseudonymization.v1`)
 * which are NOT part of the v=2 shared envelope.
 *
 * The `ar.erasure.v1` MANDATORY rule under `arr.gdpr.art17.erasure-finalized`
 * is enforced by the factory's profile-keyed `tsa_mandate` map below (fires
 * when the caller passes `opts.profile`). The doc's "other ARR events →
 * RECOMMENDED" rule (FAMILY-CONSISTENCY §2) IS enforced post-verify by
 * `applyArrTsaMandate` in `index.ts` (lines 74–81), which upgrades
 * `tsa_absent` → `tsa_recommended` for v=2 results outside the MANDATORY
 * profile path.
 *
 * ARR's envelope-v2 path does NOT structurally validate `body` today (per-
 * event body validation lives in `verify-single.ts`). The body schema below
 * is a type-narrowing pass-through that mirrors the existing verifier
 * behavior, preserving byte-equal output.
 */

import {
  defineFamily,
  type FamilyManifest,
  type BodyValidator,
} from "@dekimuhq/anchors-envelope";
import {
  validateGdprArt17ErasureFinalizedProfile,
  validateGdprArt5eProfile,
  validateHipaaRetentionProfile,
  validateKycRetentionProfile,
  validateSoxRetentionProfile,
  validateMifid2RetentionProfile,
  validateAiActArt10Profile,
} from "@dekimuhq/arr-profiles";
import type { AnyARRReceipt } from "./types.ts";

const bodySchema: BodyValidator<AnyARRReceipt> = {
  validate(body) {
    if (typeof body !== "object" || body === null) {
      return { ok: false, reason: "body.invalid" };
    }
    return { ok: true, value: body as AnyARRReceipt };
  },
};

/**
 * Frozen ARR family manifest. Identity + invariants pulled from
 * `meta/FAMILY-CONSISTENCY.md` (chip #3, status_list_slot=3, subject MUST
 * be present `"sha256:<hex>"` on every event, TSA `free` upgrade path —
 * per-profile MANDATORY enforcement is handled by tsa-mandate.ts).
 *
 * Consumers in `arr-verifier` and `arr-issuer-kit` import this manifest
 * rather than re-declaring the same constants. Public API of both packages
 * is unchanged.
 */
export const arrFamily: FamilyManifest<AnyARRReceipt> = defineFamily<AnyARRReceipt>({
  acronym: "ARR",
  name: "Anchored Retention Receipts",
  claim_types: [
    "ar.erasure.v1",
    "ar.expiry.v1",
    "ar.hold.v1",
    "ar.anonymization.v1",
    "ar.archive.v1",
    "ar.batch.v1",
  ],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/arr",

  chip: 3,
  status_list_slot: 3,
  subject_presence: "must-be-present",
  tsa_upgrade_path: "free",

  body_schema: bodySchema,

  profiles: {
    "arr.gdpr.art17.erasure-finalized": validateGdprArt17ErasureFinalizedProfile,
    "arr.gdpr.art5e": validateGdprArt5eProfile,
    "arr.hipaa.retention": validateHipaaRetentionProfile,
    "arr.kyc.retention": validateKycRetentionProfile,
    "arr.sox.retention": validateSoxRetentionProfile,
    "arr.mifid2.retention": validateMifid2RetentionProfile,
    "arr.aiact.art10": validateAiActArt10Profile,
  },

  tsa_mandate: {
    "arr.gdpr.art17.erasure-finalized": "mandatory",
  },

  continuity: true,
  batch: true,
  predicate_recommended: false,
});
