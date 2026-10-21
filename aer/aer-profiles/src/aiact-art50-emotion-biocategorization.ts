/**
 * `aiact.art50.emotion_biocategorization` profile validator — AER spec §5.6.
 *
 * Emotion recognition / biometric categorisation disclosure (AI Act Art 50(3)).
 * Subjects must be informed when these systems are used on them.
 *
 * v1 invariants enforced here:
 *   - `body.event_type === "transparency"`
 *   - `body.disclosure_type` ∈ {emotion_recognition, biometric_categorisation}
 */

import type { AerBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART50_EMOTION_BIOCATEGORIZATION_PROFILE_ID = "aiact.art50.emotion_biocategorization" as const;

const EMOTION_BIO_TYPES = new Set([
  "emotion_recognition",
  "biometric_categorisation",
]);

export function validateAiactArt50EmotionBiocategorization(body: AerBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "transparency") {
    errors.push("aiact.art50.emotion_biocategorization.wrong_event_type");
    return { errors };
  }

  if (!EMOTION_BIO_TYPES.has(body.disclosure_type)) {
    errors.push("aiact.art50.emotion_biocategorization.wrong_disclosure_type");
  }

  return { errors };
}

export const validateAiactArt50EmotionBiocategorizationProfile = makeProfileAdapter(
  AIACT_ART50_EMOTION_BIOCATEGORIZATION_PROFILE_ID,
  (body) => validateAiactArt50EmotionBiocategorization(body as AerBody),
);
