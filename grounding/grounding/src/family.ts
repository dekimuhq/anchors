/**
 * AGrR family manifest — defineFamily() wiring. Chip 18, ar.grounding.v1.
 * subject_presence "must-be-null"; status_list_slot null (non-revocable);
 * TSA optional. Distinct from AQR (quality eval), AER (conformity), and AGR (input screening).
 * One profile: grounding.rag (citation-binding + lexical grounding-support provenance for RAG answers).
 */
import { defineFamily, type FamilyManifest } from "@dekimuhq/anchors-envelope";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import { validateGroundingRag } from "@dekimuhq/grounding-profiles";
import { groundingBodyValidator } from "./body-validator.ts";
import type { AGrRBody } from "./types.ts";

const groundingRagProfile = makeProfileAdapter("grounding.rag", validateGroundingRag);

export const groundingFamily: FamilyManifest<AGrRBody> = defineFamily<AGrRBody>({
  acronym: "AGrR",
  name: "Anchored Grounding Receipts",
  claim_types: ["ar.grounding.v1"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/grounding",
  chip: 18,
  status_list_slot: null,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",
  body_schema: groundingBodyValidator,
  profiles: {
    "grounding.rag": groundingRagProfile,
  },
  tsa_mandate: {},
  continuity: false,
});
