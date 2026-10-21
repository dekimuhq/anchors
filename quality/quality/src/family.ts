/**
 * AQR family manifest — defineFamily() wiring. Chip 16, ar.quality.v1.
 * subject_presence "must-be-null"; status_list_slot null (non-revocable);
 * TSA optional. Distinct from AER (ar.evaluation.v1, AI Act conformity).
 */
import { defineFamily, type FamilyManifest } from "@dekimuhq/anchors-envelope";
import { validateQualityOutputProfile, validateQualityReleaseProfile } from "@dekimuhq/quality-profiles";
import { qualityBodyValidator } from "./body-validator.ts";
import type { AQRBody } from "./types.ts";

export const qualityFamily: FamilyManifest<AQRBody> = defineFamily<AQRBody>({
  acronym: "AQR",
  name: "Anchored Quality Receipts",
  claim_types: ["ar.quality.v1"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/quality",
  chip: 16,
  status_list_slot: null,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",
  body_schema: qualityBodyValidator,
  profiles: {
    "quality.output": validateQualityOutputProfile,
    "quality.release": validateQualityReleaseProfile,
  },
  tsa_mandate: {},
  continuity: false,
});
