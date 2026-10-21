/**
 * `aiact.art43.internal` profile validator — AER spec §5.1.
 *
 * Internal control conformity assessment (AI Act Art 43(2)).
 * Provider self-certifies without a notified body.
 *
 * v1 invariants enforced here:
 *   - `body.event_type === "conformity"`
 *   - `body.assessment_route === "internal_control"`
 *   - `body.notified_body_id === null`
 *   - `body.risk_management_system_hash` non-empty
 *   - `body.data_governance_hash` non-empty
 */

import type { AerBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART43_INTERNAL_PROFILE_ID = "aiact.art43.internal" as const;

export function validateAiactArt43Internal(body: AerBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "conformity") {
    errors.push("aiact.art43.internal.wrong_event_type");
    return { errors };
  }

  if (body.assessment_route !== "internal_control") {
    errors.push("aiact.art43.internal.wrong_assessment_route");
  }

  if (body.notified_body_id !== null) {
    errors.push("aiact.art43.internal.notified_body_id_must_be_null");
  }

  if (typeof body.risk_management_system_hash !== "string" || body.risk_management_system_hash.trim() === "") {
    errors.push("aiact.art43.internal.risk_management_system_hash_missing");
  }

  if (typeof body.data_governance_hash !== "string" || body.data_governance_hash.trim() === "") {
    errors.push("aiact.art43.internal.data_governance_hash_missing");
  }

  return { errors };
}

export const validateAiactArt43InternalProfile = makeProfileAdapter(
  AIACT_ART43_INTERNAL_PROFILE_ID,
  (body) => validateAiactArt43Internal(body as AerBody),
);
