/**
 * ar.compliance.v1 family manifest — workspace-level Proof-of-Compliance bundle.
 * subject_presence "must-be-null" (workspace-level, not per-data-subject);
 * status_list_slot null (non-revocable in this slice — see spec §8 non-goals);
 * single profile, no sub-profile validators.
 */
import { defineFamily, type FamilyManifest } from "@dekimuhq/anchors-envelope";
import { complianceBodyValidator } from "./body-validator.ts";
import type { ComplianceBundleBody } from "./types.ts";

export const complianceFamily: FamilyManifest<ComplianceBundleBody> = defineFamily<ComplianceBundleBody>({
  acronym: "ACBR",
  name: "Anchored Compliance Bundle Receipts",
  claim_types: ["ar.compliance.v1"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/compliance",
  chip: 21,
  status_list_slot: null,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",
  body_schema: complianceBodyValidator,
  profiles: {},
  tsa_mandate: {},
  continuity: false,
});
