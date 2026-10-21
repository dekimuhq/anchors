/**
 * ACR family manifest — Phase A.3 step 3 adoption of `defineFamily()`.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 *
 * ACR is the fourth family member (after the ALR canary at `a7ae33c`, the APR
 * step at Phase A.3 step 1, and the ARR step at Phase A.3 step 2) to consume
 * `defineFamily()` from `@dekimuhq/anchors-envelope`. Phase A.3 is
 * non-breaking — the public API of both `@dekimuhq/acr` and its
 * `@dekimuhq/acr/issue` subpath stays byte-equal. The manifest is wired in
 * under the hood:
 *
 *   - `envelope-v2.ts` uses `acrFamily.isOwnedClaimType()` to gate the
 *     `wrong_protocol` reason in place of the hand-rolled `ACR_CLAIM_TYPE_SET`.
 *   - `acr-issuer-kit/mint-v2.ts` reads its per-event `claim_type` literal
 *     from `acrFamily.meta.claim_types` (three entries).
 *
 * ACR has three v=2 claim_types: `ar.consent.v1`, `ar.modification.v1`,
 * `ar.withdrawal.v1`.
 *
 * Per-profile MANDATORY TSA enforcement (e.g. `acr.esig.accept@qes` requires
 * eIDAS QTS) lives in the existing profile validators and TSA mandate matrix,
 * not in the manifest — the manifest records the family-wide upgrade path
 * classification only.
 *
 * ACR's envelope-v2 path does NOT structurally validate `body` today (per-
 * event body validation lives in `verify.ts` and the profile validators).
 * The body schema below is a type-narrowing pass-through that mirrors the
 * existing verifier behavior, preserving byte-equal output.
 */

import {
  defineFamily,
  type FamilyManifest,
  type BodyValidator,
} from "@dekimuhq/anchors-envelope";
import { validateEsigAcceptQesProfile } from "@dekimuhq/acr-profiles";
import type { ACRReceipt } from "./types.ts";

const bodySchema: BodyValidator<ACRReceipt> = {
  validate(body) {
    if (typeof body !== "object" || body === null) {
      return { ok: false, reason: "body.invalid" };
    }
    return { ok: true, value: body as ACRReceipt };
  },
};

/**
 * Frozen ACR family manifest. Identity + invariants pulled from
 * `meta/FAMILY-CONSISTENCY.md` (chip #2, status_list_slot=2, subject MUST be
 * present `"sha256:<hex>"` HMAC-salted commit on every event, TSA `free`
 * upgrade path — per-profile MANDATORY enforcement is handled separately
 * by profile validators).
 *
 * Consumers in `acr-verifier` and `acr-issuer-kit` import this manifest
 * rather than re-declaring the same constants. Public API of both packages
 * is unchanged.
 */
export const acrFamily: FamilyManifest<ACRReceipt> = defineFamily<ACRReceipt>({
  acronym: "ACR",
  name: "Anchored Consent Receipts",
  claim_types: [
    "ar.consent.v1",
    "ar.modification.v1",
    "ar.withdrawal.v1",
  ],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/acr",

  chip: 2,
  status_list_slot: 2,
  subject_presence: "must-be-present",
  tsa_upgrade_path: "free",

  body_schema: bodySchema,

  profiles: {
    "acr.esig.accept@qes": validateEsigAcceptQesProfile,
  },

  tsa_mandate: {
    "acr.esig.accept@qes": "mandatory",
  },

  continuity: true,
  batch: false,
  predicate_recommended: false,
});
