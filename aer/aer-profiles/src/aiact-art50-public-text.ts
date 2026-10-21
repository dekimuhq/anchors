/**
 * `aiact.art50.public_text` profile validator — AER spec §5.7.
 *
 * AI-generated text disclosure for matters of public interest (AI Act Art 50(4)).
 * Large-scale public-interest text must be machine-labelled.
 *
 * v1 invariants enforced here:
 *   - `body.event_type === "transparency"`
 *   - `body.disclosure_type === "ai_generated_text_public_interest"`
 *   - `body.disclosure_text_hash` non-empty
 */

import type { AerBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART50_PUBLIC_TEXT_PROFILE_ID = "aiact.art50.public_text" as const;

export function validateAiactArt50PublicText(body: AerBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "transparency") {
    errors.push("aiact.art50.public_text.wrong_event_type");
    return { errors };
  }

  if (body.disclosure_type !== "ai_generated_text_public_interest") {
    errors.push("aiact.art50.public_text.wrong_disclosure_type");
  }

  if (typeof body.disclosure_text_hash !== "string" || body.disclosure_text_hash.trim() === "") {
    errors.push("aiact.art50.public_text.disclosure_text_hash_missing");
  }

  return { errors };
}

export const validateAiactArt50PublicTextProfile = makeProfileAdapter(
  AIACT_ART50_PUBLIC_TEXT_PROFILE_ID,
  (body) => validateAiactArt50PublicText(body as AerBody),
);
