/**
 * AUTO-GENERATED from ar.consent.v1.anchor.json
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
import type { ACRBody } from "./types.ts";

const bodySchema: BodyValidator<ACRBody> = {
  validate(body) {
    if (typeof body !== "object" || body === null) {
      return { ok: false, reason: "body.invalid" };
    }
    // TODO: Implement structural body validation
    return { ok: true, value: body as ACRBody };
  },
};

// TODO: Implement compose callback
// Links to: ar.notice.v1

export const acrFamily: FamilyManifest<ACRBody> = defineFamily<ACRBody>({
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

  // TODO: Wire profile validators
  profiles: {},

  // TODO: Wire TSA mandate map (if non-trivial)
  tsa_mandate: {},

  continuity: true,
  // TODO: Wire compose callback
  batch: false,
  predicate_recommended: false,
});
