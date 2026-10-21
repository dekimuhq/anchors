/**
 * AGR family manifest — defineFamily() wiring. Chip 17, ar.guard.v1.
 * subject_presence "must-be-null"; status_list_slot null (non-revocable);
 * TSA optional. Distinct from AQR (quality eval) and AER (conformity).
 * One profile: guard.input (deterministic input-screening verdict provenance).
 */
import { defineFamily, type FamilyManifest } from "@dekimuhq/anchors-envelope";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import { validateGuardInput } from "@dekimuhq/guard-profiles";
import { guardBodyValidator } from "./body-validator.ts";
import type { AGRBody } from "./types.ts";

const guardInputProfile = makeProfileAdapter("guard.input", validateGuardInput);

export const guardFamily: FamilyManifest<AGRBody> = defineFamily<AGRBody>({
  acronym: "AGR",
  name: "Anchored Guard Verdicts",
  claim_types: ["ar.guard.v1"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/guard",
  chip: 17,
  status_list_slot: null,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",
  body_schema: guardBodyValidator,
  profiles: {
    "guard.input": guardInputProfile,
  },
  tsa_mandate: {},
  continuity: false,
});
