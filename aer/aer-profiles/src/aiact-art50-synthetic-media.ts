/**
 * `aiact.art50.synthetic_media` profile validator — AER spec §5.5.
 *
 * Synthetic content disclosure + watermarking (AI Act Art 50(2)).
 * AI-generated or manipulated content must carry a machine-readable mark.
 *
 * v1 invariants enforced here:
 *   - `body.event_type === "transparency"`
 *   - `body.disclosure_type` ∈ {synthetic_audio, synthetic_image, synthetic_video,
 *     deepfake_recognisable_person, deepfake_artistic}
 *   - `body.watermark_scheme` ≠ "none" (Art 50(2) requires machine-readable mark)
 *   - `body.watermark_sample_commit` non-empty
 */

import type { AerBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART50_SYNTHETIC_MEDIA_PROFILE_ID = "aiact.art50.synthetic_media" as const;

const SYNTHETIC_MEDIA_TYPES = new Set([
  "synthetic_audio",
  "synthetic_image",
  "synthetic_video",
  "deepfake_recognisable_person",
  "deepfake_artistic",
]);

export function validateAiactArt50SyntheticMedia(body: AerBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "transparency") {
    errors.push("aiact.art50.synthetic_media.wrong_event_type");
    return { errors };
  }

  if (!SYNTHETIC_MEDIA_TYPES.has(body.disclosure_type)) {
    errors.push("aiact.art50.synthetic_media.wrong_disclosure_type");
  }

  if (body.watermark_scheme === "none") {
    errors.push("aiact.art50.synthetic_media.watermark_scheme_required");
  }

  if (
    body.watermark_sample_commit === null ||
    typeof body.watermark_sample_commit !== "string" ||
    body.watermark_sample_commit.trim() === ""
  ) {
    errors.push("aiact.art50.synthetic_media.watermark_sample_commit_missing");
  }

  return { errors };
}

export const validateAiactArt50SyntheticMediaProfile = makeProfileAdapter(
  AIACT_ART50_SYNTHETIC_MEDIA_PROFILE_ID,
  (body) => validateAiactArt50SyntheticMedia(body as AerBody),
);
