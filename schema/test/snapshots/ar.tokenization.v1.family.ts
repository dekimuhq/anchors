/**
 * AUTO-GENERATED from ar.tokenization.v1.anchor.json
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
import type { ATokRBody } from "./types.ts";

const bodySchema: BodyValidator<ATokRBody> = {
  validate(body) {
    if (typeof body !== "object" || body === null) {
      return { ok: false, reason: "body.invalid" };
    }
    // TODO: Implement structural body validation
    return { ok: true, value: body as ATokRBody };
  },
};

// TODO: Implement compose callback
// Links to: ar.subject_rights.v1, ar.erasure.v1, ar.lineage.v1, ar.purpose.v1

export const atokrFamily: FamilyManifest<ATokRBody> = defineFamily<ATokRBody>({
  acronym: "ATokR",
  name: "Anchored Tokenization Receipts",
  claim_types: ["ar.tokenization.v1"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/atokr",

  chip: 14,
  status_list_slot: 13,
  subject_presence: "must-be-present",
  tsa_upgrade_path: "free",

  body_schema: bodySchema,

  // TODO: Wire profile validators
  profiles: {},

  // TODO: Wire TSA mandate map (if non-trivial)
  tsa_mandate: {},

  continuity: true,
  // TODO: Wire compose callback
  batch: false,
  predicate_recommended: false,
});
