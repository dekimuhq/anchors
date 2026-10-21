/**
 * AER family manifest — `defineFamily()` wiring.
 *
 * AER is the 7th family member (chip 7, status_list_slot 11,
 * ar.evaluation.v1). Wiring choices:
 *
 *   - `subject_presence: "either"` + `subject_presence_check` — per-event
 *     split: conformity → null, transparency → sha256. Uses `"either"` as the
 *     universal rule (accepted value by the factory) because the per-event
 *     callback fully overrides it.
 *   - `tsa_mandate` — omitted at factory level; 9 profiles registered via
 *     aer-profiles. TSA mandate for conformity events is RECOMMENDED per
 *     FAMILY-CONSISTENCY §2, but verifier-side enforcement (the
 *     `tsa_recommended` warning) is NOT yet wired — `composeAer` does
 *     chain-walk + transparency-backing only. Same Phase-4 event-keyed-mandate
 *     deferral as ATR/ASR.
 *   - `continuity: true`
 *   - `compose` — wired to `composeAer` (stub, Task 8 implements chain walk)
 */

import {
  defineFamily,
  type FamilyManifest,
  type SubjectPresenceCheck,
} from "@dekimuhq/anchors-envelope";
import {
  validateAiactArt43InternalProfile,
  validateAiactArt43ThirdpartyProfile,
  validateAiactArt43FrAssessmentProfile,
  validateAiactArt50ChatbotProfile,
  validateAiactArt50SyntheticMediaProfile,
  validateAiactArt50EmotionBiocategorizationProfile,
  validateAiactArt50PublicTextProfile,
  validateAiactArt52GpaiProfile,
  validateNistAimrfProfile,
} from "@dekimuhq/aer-profiles";
import { aerBodyValidator } from "./body-validator.ts";
import { composeAer } from "./compose.ts";
import { checkAerSubjectPresence } from "./subject-presence.ts";
import type { AerBody } from "./types.ts";

const subjectPresenceCheck: SubjectPresenceCheck = ({ subject, body }) => {
  const r = checkAerSubjectPresence({ subject, body });
  if (r.ok) return { ok: true };
  const reason =
    r.reason === "subject_must_be_present"
      ? "subject_missing"
      : r.reason === "subject_must_be_sha256"
        ? "subject_invalid_form"
        : "subject_present";
  return { ok: false, reason };
};

export const aerFamily: FamilyManifest<AerBody> = defineFamily<AerBody>({
  acronym: "AER",
  name: "Anchored Evaluation Receipts",
  claim_types: ["ar.evaluation.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/aer",

  chip: 7,
  status_list_slot: 11,
  // "either" is the accepted universal rule; the per-event callback overrides it.
  subject_presence: "either",
  subject_presence_check: subjectPresenceCheck,
  tsa_upgrade_path: "free",

  body_schema: aerBodyValidator,

  profiles: {
    "aiact.art43.internal": validateAiactArt43InternalProfile,
    "aiact.art43.thirdparty": validateAiactArt43ThirdpartyProfile,
    "aiact.art43.fr_assessment": validateAiactArt43FrAssessmentProfile,
    "aiact.art50.chatbot": validateAiactArt50ChatbotProfile,
    "aiact.art50.synthetic_media": validateAiactArt50SyntheticMediaProfile,
    "aiact.art50.emotion_biocategorization": validateAiactArt50EmotionBiocategorizationProfile,
    "aiact.art50.public_text": validateAiactArt50PublicTextProfile,
    "aiact.art52.gpai": validateAiactArt52GpaiProfile,
    "nist.aimrf.profile": validateNistAimrfProfile,
  },

  continuity: true,
  compose: composeAer,
});
