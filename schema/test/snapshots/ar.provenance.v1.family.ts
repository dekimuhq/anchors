/**
 * AUTO-GENERATED from ar.provenance.v1.anchor.json
 * Generated: [TIMESTAMP]
 *
 * Scaffold for defineFamily() wiring. Fill in TODO stubs with
 * imperative logic (body validation, profile validators, compose).
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
    // TODO: Implement structural body validation
    return { ok: true, value: body as APRBody };
  },
};

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

  // TODO: Wire profile validators
  profiles: {},

  // TODO: Wire TSA mandate map (if non-trivial)
  tsa_mandate: {},

  continuity: true,
  batch: false,
  predicate_recommended: false,
});
