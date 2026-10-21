/**
 * AUTO-GENERATED from ar.transfer.v1.anchor.json
 * Generated: [TIMESTAMP]
 *
 * Scaffold for defineFamily() wiring. Fill in TODO stubs with
 * imperative logic (body validation, profile validators, compose).
 */

import {
  defineFamily,
  type FamilyManifest,
  type BodyValidator,
  type SubjectPresenceCheck,
} from "@dekimuhq/anchors-envelope";
import type { ATRBody } from "./types.ts";

const bodySchema: BodyValidator<ATRBody> = {
  validate(body) {
    if (typeof body !== "object" || body === null) {
      return { ok: false, reason: "body.invalid" };
    }
    // TODO: Implement structural body validation
    return { ok: true, value: body as ATRBody };
  },
};

// TODO: Implement subject_presence_check for per-event splitting
// Overrides from manifest:
//   arrangement: must-be-null — Arrangement is data-flow-level, not subject-level.
//   transfer: must-be-present — sha256 batch root or per-subject commit.
//   tia: must-be-null
//   suspension: must-be-null
const subjectPresenceCheck: SubjectPresenceCheck = ({ subject, body }) => {
  // TODO: Check event_type from body and enforce per-event rules
  return { ok: true };
};

export const atrFamily: FamilyManifest<ATRBody> = defineFamily<ATRBody>({
  acronym: "ATR",
  name: "Anchored Transfer Receipts",
  claim_types: ["ar.transfer.v1"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/atr",

  chip: 5,
  status_list_slot: 9,
  subject_presence: "either",
  subject_presence_check: subjectPresenceCheck,
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
