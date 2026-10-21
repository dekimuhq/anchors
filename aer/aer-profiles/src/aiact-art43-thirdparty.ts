/**
 * `aiact.art43.thirdparty` profile validator — AER spec §5.2.
 *
 * Third-party notified body conformity assessment (AI Act Art 43(1)).
 * Required for Annex III high-risk systems not eligible for internal control.
 *
 * v1 invariants enforced here:
 *   - `body.event_type === "conformity"`
 *   - `body.assessment_route === "thirdparty_notified_body"`
 *   - `body.notified_body_id` non-null and matches `NB-XXXX` pattern
 *   - `body.harmonized_standards` non-empty array
 */

import type { AerBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART43_THIRDPARTY_PROFILE_ID = "aiact.art43.thirdparty" as const;

const NB_ID_RE = /^NB-\d{4}$/;

export function validateAiactArt43Thirdparty(body: AerBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "conformity") {
    errors.push("aiact.art43.thirdparty.wrong_event_type");
    return { errors };
  }

  if (body.assessment_route !== "thirdparty_notified_body") {
    errors.push("aiact.art43.thirdparty.wrong_assessment_route");
  }

  if (body.notified_body_id === null || !NB_ID_RE.test(body.notified_body_id)) {
    errors.push("aiact.art43.thirdparty.notified_body_id_invalid");
  }

  if (!Array.isArray(body.harmonized_standards) || body.harmonized_standards.length === 0) {
    errors.push("aiact.art43.thirdparty.harmonized_standards_empty");
  }

  return { errors };
}

export const validateAiactArt43ThirdpartyProfile = makeProfileAdapter(
  AIACT_ART43_THIRDPARTY_PROFILE_ID,
  (body) => validateAiactArt43Thirdparty(body as AerBody),
);
