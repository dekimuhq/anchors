/**
 * `aiact.art50.chatbot` profile validator — AER spec §5.4.
 *
 * Chatbot interaction disclosure (AI Act Art 50(1)).
 * Users interacting with AI systems must be informed they are doing so.
 *
 * v1 invariants enforced here:
 *   - `body.event_type === "transparency"`
 *   - `body.disclosure_type === "chatbot"`
 *   - `body.disclosure_text_hash` non-empty
 *   - `body.disclosure_locale` non-empty
 *   - `body.watermark_scheme === "none"` (chatbots don't need watermarks)
 */

import type { AerBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART50_CHATBOT_PROFILE_ID = "aiact.art50.chatbot" as const;

export function validateAiactArt50Chatbot(body: AerBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "transparency") {
    errors.push("aiact.art50.chatbot.wrong_event_type");
    return { errors };
  }

  if (body.disclosure_type !== "chatbot") {
    errors.push("aiact.art50.chatbot.wrong_disclosure_type");
  }

  if (typeof body.disclosure_text_hash !== "string" || body.disclosure_text_hash.trim() === "") {
    errors.push("aiact.art50.chatbot.disclosure_text_hash_missing");
  }

  if (typeof body.disclosure_locale !== "string" || body.disclosure_locale.trim() === "") {
    errors.push("aiact.art50.chatbot.disclosure_locale_missing");
  }

  if (body.watermark_scheme !== "none") {
    errors.push("aiact.art50.chatbot.watermark_scheme_must_be_none");
  }

  return { errors };
}

export const validateAiactArt50ChatbotProfile = makeProfileAdapter(
  AIACT_ART50_CHATBOT_PROFILE_ID,
  (body) => validateAiactArt50Chatbot(body as AerBody),
);
