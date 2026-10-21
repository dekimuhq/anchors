/**
 * ALR family manifest — Phase A.2 canary adoption of `defineFamily()`.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 *
 * ALR is the first family member to consume `defineFamily()` (shipped in
 * `@dekimuhq/anchors-envelope` 0.6.0). Phase A.2 is non-breaking — the
 * public API of `@dekimuhq/alr` and its `@dekimuhq/alr/issue` subpath
 * stays byte-equal. The manifest is wired in under the hood:
 *
 *   - `envelope-v2.ts` uses `alrFamily.isOwnedClaimType()` to gate the
 *     `wrong_protocol` reason in place of a hand-rolled `Set`.
 *   - `subject-presence.ts` delegates to `alrFamily.checkSubjectPresence()`.
 *   - `alr-issuer-kit/mint-v2.ts` reads its `claim_type` literal from
 *     `alrFamily.meta.claim_types[0]`.
 *
 * Body schema validation routes through `verifyAlrBody` — the manifest
 * adapter returns the narrowed body when valid and the first error code
 * (preserving the spec §4.5 "first failure wins" rule).
 *
 * Composition `walkParents` returns the APR receipt IDs cited via
 * `body.parents[].parent_apr_id` (origin terminators per spec §6.2 step 3).
 * `superseded_by` and `disclosed` bodies carry no lineage parents and
 * return `[]`.
 */

import {
  defineFamily,
  type FamilyManifest,
  type BodyValidator,
} from "@dekimuhq/anchors-envelope";
import {
  validateGdprArt13TransparencyProfile,
  validateAiactArt13TransparencyProfile,
  validateAiactArt53GpaiTrainingProfile,
  validateC2paNonMediaProfile,
  validateDisclosureRecipientsProfile,
} from "@dekimuhq/alr-profiles";
import { verifyAlrBody } from "./verify-single.ts";
import { extractAprComposition } from "./composition.ts";
import type { AlrBody } from "./types.ts";

const bodySchema: BodyValidator<AlrBody> = {
  validate(body) {
    const r = verifyAlrBody(body);
    if (r.valid && r.body !== null) return { ok: true, value: r.body };
    return { ok: false, reason: r.errors[0] ?? "body.invalid" };
  },
};

function walkAlrParents(body: unknown): readonly string[] {
  if (typeof body !== "object" || body === null) return [];
  const summary = extractAprComposition(body as AlrBody);
  return summary.aprRefs;
}

/**
 * Frozen ALR family manifest. Identity + invariants pulled from
 * `meta/FAMILY-CONSISTENCY.md` (chip #9, status_list_slot=1, subject MUST
 * be null on every event_type, TSA OPTIONAL via FreeTSA upgrade path).
 *
 * Consumers in `alr-verifier` and `alr-issuer-kit` import this manifest
 * rather than re-declaring the same constants. Public API of both
 * packages is unchanged.
 */
export const alrFamily: FamilyManifest<AlrBody> = defineFamily<AlrBody>({
  acronym: "ALR",
  name: "Anchored Lineage Receipts",
  claim_types: ["ar.lineage.v1"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/alr",

  chip: 9,
  status_list_slot: 1,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",

  body_schema: bodySchema,

  profiles: {
    "gdpr.art13.transparency": validateGdprArt13TransparencyProfile,
    "aiact.art13.transparency": validateAiactArt13TransparencyProfile,
    "aiact.art53.gpai-training": validateAiactArt53GpaiTrainingProfile,
    "c2pa.non-media": validateC2paNonMediaProfile,
    "disclosure.recipients": validateDisclosureRecipientsProfile,
  },

  continuity: true,
  batch: false,
  predicate_recommended: false,

  composition: {
    walkParents: walkAlrParents,
  },
});
