/**
 * AScR family manifest. Chip 22, ar.screening.v1. must-be-null subject;
 * Status-List non-consumer; TSA optional. One profile: screening.list.
 */
import { defineFamily, type FamilyManifest } from "@dekimuhq/anchors-envelope";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import { validateScreeningList } from "@dekimuhq/screening-profiles";
import { screeningBodyValidator } from "./body-validator.ts";
import type { AScRBody } from "./types.ts";

const screeningListProfile = makeProfileAdapter("screening.list", validateScreeningList);

export const screeningFamily: FamilyManifest<AScRBody> = defineFamily<AScRBody>({
  acronym: "AScR",
  name: "Anchored Screening Receipts",
  claim_types: ["ar.screening.v1"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/screening",
  chip: 22,
  status_list_slot: null,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",
  body_schema: screeningBodyValidator,
  profiles: { "screening.list": screeningListProfile },
  tsa_mandate: {},
  continuity: false,
});
