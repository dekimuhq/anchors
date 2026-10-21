/**
 * APR family manifest — Phase A.3 step 1 adoption of `defineFamily()`.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 *
 * APR is the second family member (after the ALR canary at `a7ae33c`) to
 * consume `defineFamily()` from `@dekimuhq/anchors-envelope`. Phase A.3 is
 * non-breaking — the public API of `@dekimuhq/apr` and its
 * `@dekimuhq/apr/issue` subpath stays byte-equal. The manifest is wired in
 * under the hood:
 *
 *   - `envelope-v2.ts` uses `aprFamily.isOwnedClaimType()` to gate the
 *     `wrong_protocol` reason in place of the hand-rolled `APR_CLAIM_TYPE_SET`.
 *   - `apr-issuer-kit/mint-v2.ts` reads its `claim_type` literal from
 *     `aprFamily.meta.claim_types[0]`.
 *
 * APR does NOT consume W3C Status List 2021 (FAMILY-CONSISTENCY §4 — provenance
 * receipts are non-revocable by design). `status_list_slot` is `null`; the
 * factory was extended in `@dekimuhq/anchors-envelope` 0.6.2 to accept the
 * non-consumer form.
 *
 * APR's envelope-v2 path does NOT structurally validate `body` today (the
 * `APRBody` shape is enforced at issuer-kit mint time, not at verifier
 * envelope time). The body schema below is a type-narrowing pass-through —
 * it matches the verifier's existing behavior. A future hardening pass
 * could replace it with a runtime check; until then this preserves
 * byte-equal output.
 */

import {
  defineFamily,
  type FamilyManifest,
  type BodyValidator,
} from "@dekimuhq/anchors-envelope";
import type { APRBody } from "./types.ts";

const bodySchema: BodyValidator<APRBody> = {
  validate(body) {
    if (typeof body !== "object" || body === null) {
      return { ok: false, reason: "body.invalid" };
    }
    return { ok: true, value: body as APRBody };
  },
};

/**
 * Frozen APR family manifest. Identity + invariants pulled from
 * `meta/FAMILY-CONSISTENCY.md` (chip #1, status_list_slot=null since APR is
 * the canonical Status List 2021 non-consumer, subject MUST be present
 * free-form on every event, TSA OPTIONAL).
 *
 * Consumers in `apr-verifier` and `apr-issuer-kit` import this manifest
 * rather than re-declaring the same constants. Public API of both packages
 * is unchanged.
 */
export const aprFamily: FamilyManifest<APRBody> = defineFamily<APRBody>({
  acronym: "APR",
  name: "Agent Provenance Receipts",
  claim_types: ["ar.provenance.v1"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/apr",

  chip: 1,
  status_list_slot: null,
  subject_presence: "must-be-present",
  tsa_upgrade_path: "free",

  body_schema: bodySchema,

  continuity: true,
  batch: false,
  predicate_recommended: false,
});
