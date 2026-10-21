/**
 * AAR family manifest — defineFamily() adoption.
 *
 * Chip 8, status_list_slot 12, claim_type ar.attestation.v1.
 * 8 eIDAS profiles registered. Continuity enabled.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/aar
 */

import {
  defineFamily,
  type FamilyManifest,
  type SubjectPresenceCheck,
} from "@dekimuhq/anchors-envelope";
import {
  validateEidasQesProfile,
  validateEidasQesealProfile,
  validateEidasQtsProfile,
  validateEidasQeregProfile,
  validateEidasQcertNaturalProfile,
  validateEidasQcertLegalProfile,
  validateEidasQwalletProfile,
  validateEidasQattestProfile,
} from "@dekimuhq/aar-profiles";
import { aarBodyValidator } from "./body-validator.ts";
import { composeAar } from "./compose.ts";
import { checkAarSubjectPresence } from "./subject-presence.ts";
import type { AarBody } from "./types.ts";

const subjectPresenceCheck: SubjectPresenceCheck = ({ subject }) => {
  const r = checkAarSubjectPresence({ subject });
  if (r.ok) return { ok: true };
  const reason =
    r.reason === "subject_must_be_present"
      ? "subject_missing"
      : "subject_invalid_form";
  return { ok: false, reason };
};

export const aarFamily: FamilyManifest<AarBody> = defineFamily<AarBody>({
  acronym: "AAR",
  name: "Anchored Attestation Receipts",
  claim_types: ["ar.attestation.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/aar",
  chip: 8,
  status_list_slot: 12,
  subject_presence: "must-be-present",
  subject_presence_check: subjectPresenceCheck,
  tsa_upgrade_path: "free",
  body_schema: aarBodyValidator,
  profiles: {
    "eidas.qes": validateEidasQesProfile,
    "eidas.qeseal": validateEidasQesealProfile,
    "eidas.qts": validateEidasQtsProfile,
    "eidas.qereg": validateEidasQeregProfile,
    "eidas.qcert.natural": validateEidasQcertNaturalProfile,
    "eidas.qcert.legal": validateEidasQcertLegalProfile,
    "eidas.qwallet": validateEidasQwalletProfile,
    "eidas.qattest": validateEidasQattestProfile,
  },
  // AAR's TSA mandate is event+service_type keyed (issuance+qts MANDATORY,
  // else RECOMMENDED — FAMILY-CONSISTENCY §2), not profile-keyed, so it cannot
  // be expressed here. Enforced as a post-step via applyAarTsaMandate in
  // index.ts, mirroring ABR/AIR.
  tsa_mandate: {},
  continuity: true,
  compose: composeAar,
});
