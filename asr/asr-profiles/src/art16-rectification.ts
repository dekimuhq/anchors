/**
 * `subject_rights.art16.rectification` profile validator — ASR spec §5.2.
 *
 * Hook: GDPR Art. 16 — right to rectification.
 *
 * v1 invariants enforced here:
 *   - On `request.fulfilled`: `body.arr_receipt_id` MUST NOT be set
 *     (Art. 17 erasure cross-link).
 *   - On `request.fulfilled`: `body.portability_format` MUST NOT be set
 *     (Art. 20 portability cross-link).
 *
 * The §5.2 canonical before-after hash structure
 * (`Sha256(canonical_old || "→" || canonical_new)`) is an issuer-side
 * convention; the on-the-wire commitment is the opaque
 * `fulfilled_artifact_hash`, already body-mandatory. The verifier cannot
 * recompute the pre-hash inputs without the original payloads.
 *
 * Art. 19 recipient-notification expectation is surfaced by the verifier's
 * chain walker (§7 step 6 — `art19_notification_missing` warning) and is
 * not a profile-validator concern.
 */

import type { AsrBody } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const ART16_RECTIFICATION_PROFILE_ID =
  "subject_rights.art16.rectification" as const;

export function validateArt16Rectification(
  body: AsrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "request.fulfilled") {
    if (body.arr_receipt_id != null && body.arr_receipt_id !== "") {
      errors.push("subject_rights.art16.rectification.arr_receipt_id.forbidden");
    }
    if (body.portability_format != null && body.portability_format !== "") {
      errors.push(
        "subject_rights.art16.rectification.portability_format.forbidden",
      );
    }
  }

  return { errors };
}

export const validateArt16RectificationProfile = makeProfileAdapter(ART16_RECTIFICATION_PROFILE_ID, (body) => validateArt16Rectification(body as AsrBody));
