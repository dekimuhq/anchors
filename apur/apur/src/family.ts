/**
 * APuR family manifest — defineFamily() wiring.
 *
 * Chip 6, status_list_slot 10, ar.purpose.v1.
 * Subject always null (processing-activity-level).
 * All TSA profiles OPTIONAL. 4 profile validators registered.
 */

import {
  defineFamily,
  type FamilyManifest,
} from "@dekimuhq/anchors-envelope";
import {
  validateGdprArt5Profile,
  validateGdprArt6_4Profile,
  validateHipaaMinimumNecessaryProfile,
  validateLgpdArt6Profile,
} from "@dekimuhq/apur-profiles";
import { apurBodyValidator } from "./body-validator.ts";
import { composeApur } from "./compose.ts";
import type { ApurBody } from "./types.ts";

export const apurFamily: FamilyManifest<ApurBody> = defineFamily<ApurBody>({
  acronym: "APuR",
  name: "Anchored Purpose Receipts",
  claim_types: ["ar.purpose.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/apur",

  chip: 6,
  status_list_slot: 10,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",

  body_schema: apurBodyValidator,

  profiles: {
    "purpose.gdpr.art5": validateGdprArt5Profile,
    "purpose.gdpr.art6_4": validateGdprArt6_4Profile,
    "purpose.hipaa.minimum_necessary": validateHipaaMinimumNecessaryProfile,
    "purpose.lgpd.art6": validateLgpdArt6Profile,
  },

  tsa_mandate: {},

  continuity: true,
  compose: composeApur,
});
