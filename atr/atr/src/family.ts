/**
 * ATR family manifest — `defineFamily()` wiring.
 *
 * Chip 5, status_list_slot 9, ar.transfer.v1. Per-event subject split
 * (transfer=sha256, others=null). TSA mandate: RECOMMENDED on
 * arrangement + suspension, OPTIONAL on transfer + tia.
 */

import {
  defineFamily,
  type FamilyManifest,
  type SubjectPresenceCheck,
} from "@dekimuhq/anchors-envelope";
import {
  validateGdprArt45AdequacyProfile,
  validateGdprArt46SccProfile,
  validateGdprArt46BcrProfile,
  validateGdprArt46IdtaProfile,
  validateGdprArt47BcrAuthorisedProfile,
  validateGdprArt49DerogationProfile,
  validateGdprDpfProfile,
  validateSchremsiiTiaProfile,
} from "@dekimuhq/atr-profiles";
import { atrBodyValidator } from "./body-validator.ts";
import { composeAtr } from "./compose.ts";
import { checkAtrSubjectPresence } from "./subject-presence.ts";
import type { AtrBody } from "./types.ts";

const subjectPresenceCheck: SubjectPresenceCheck = ({ subject, body }) => {
  const eventType = (body as Record<string, unknown>)?.event_type;
  const r = checkAtrSubjectPresence({ subject, event_type: eventType });
  if (r.ok) return { ok: true };
  const reason =
    r.reason === "subject_must_be_present"
      ? "subject_missing"
      : r.reason === "subject_must_be_null"
        ? "subject_must_be_null"
        : "subject_invalid_form";
  return { ok: false, reason };
};

export const atrFamily: FamilyManifest<AtrBody> = defineFamily<AtrBody>({
  acronym: "ATR",
  name: "Anchored Transfer Receipts",
  claim_types: ["ar.transfer.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/atr",

  chip: 5,
  status_list_slot: 9,
  subject_presence: "either",
  subject_presence_check: subjectPresenceCheck,
  tsa_upgrade_path: "free",

  body_schema: atrBodyValidator,

  profiles: {
    "gdpr.art45.adequacy": validateGdprArt45AdequacyProfile,
    "gdpr.art46.scc": validateGdprArt46SccProfile,
    "gdpr.art46.bcr": validateGdprArt46BcrProfile,
    "gdpr.art46.idta": validateGdprArt46IdtaProfile,
    "gdpr.art47.bcr_authorised": validateGdprArt47BcrAuthorisedProfile,
    "gdpr.art49.derogation": validateGdprArt49DerogationProfile,
    "gdpr.dpf": validateGdprDpfProfile,
    "schremsii.tia": validateSchremsiiTiaProfile,
  },

  // ATR TSA mandate is event-keyed (not profile-keyed) — handled by
  // getAtrTsaMandate() in tsa-mandate.ts.
  // defineFamily only accepts profile IDs as tsa_mandate keys, so omit here.

  continuity: true,
  compose: composeAtr,
});
