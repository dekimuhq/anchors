/**
 * APIIR family manifest — defineFamily() wiring. ar.redaction.v1, chip 20.
 * subject_presence "must-be-null"; status_list_slot null (non-revocable);
 * TSA optional; POLICY_OPTIONAL. Honest claim = redaction provenance, not a
 * PII-free guarantee.
 */
import { defineFamily, type FamilyManifest } from "@dekimuhq/anchors-envelope";
import { validateRedactionPromptProfile } from "@dekimuhq/redaction-profiles";
import { redactionBodyValidator } from "./body-validator.ts";
import type { APIIRBody } from "./types.ts";

export const redactionFamily: FamilyManifest<APIIRBody> = defineFamily<APIIRBody>({
  acronym: "APIIR",
  name: "Anchored PII-Redaction Receipts",
  claim_types: ["ar.redaction.v1"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/redaction",
  chip: 20,
  status_list_slot: null,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",
  body_schema: redactionBodyValidator,
  profiles: { "redaction.prompt": validateRedactionPromptProfile },
  tsa_mandate: {},
  continuity: false,
});
