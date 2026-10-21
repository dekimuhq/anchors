/**
 * `aiact.art43.fr_assessment` profile validator — AER spec §5.3.
 *
 * Fundamental Rights Impact Assessment (AI Act Art 27).
 * Deployers of high-risk AI systems must conduct and record an FRIA.
 *
 * v1 invariants enforced here:
 *   - `body.event_type === "conformity"`
 *   - `body.assessment_route === "fundamental_rights"`
 *   - `body.fundamental_rights_hash` non-null and non-empty
 */

import type { AerBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART43_FR_ASSESSMENT_PROFILE_ID = "aiact.art43.fr_assessment" as const;

export function validateAiactArt43FrAssessment(body: AerBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "conformity") {
    errors.push("aiact.art43.fr_assessment.wrong_event_type");
    return { errors };
  }

  if (body.assessment_route !== "fundamental_rights") {
    errors.push("aiact.art43.fr_assessment.wrong_assessment_route");
  }

  if (
    body.fundamental_rights_hash === null ||
    typeof body.fundamental_rights_hash !== "string" ||
    body.fundamental_rights_hash.trim() === ""
  ) {
    errors.push("aiact.art43.fr_assessment.fundamental_rights_hash_missing");
  }

  return { errors };
}

export const validateAiactArt43FrAssessmentProfile = makeProfileAdapter(
  AIACT_ART43_FR_ASSESSMENT_PROFILE_ID,
  (body) => validateAiactArt43FrAssessment(body as AerBody),
);
