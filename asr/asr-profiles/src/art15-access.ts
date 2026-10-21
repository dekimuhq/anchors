/**
 * `subject_rights.art15.access` profile validator — ASR spec §5.1.
 *
 * Hook: GDPR Art. 15 — right of access.
 *
 * v1 invariants enforced here:
 *   - On `request.fulfilled`: `body.arr_receipt_id` MUST NOT be set
 *     (the Art. 17 erasure cross-link belongs to that profile only).
 *   - On `request.fulfilled`: `body.portability_format` MUST NOT be set
 *     (Art. 20 portability cross-link belongs to that profile only).
 *
 * Per-event MANDATORY fields (`fulfilled_artifact_hash`, `fulfilment_uri`)
 * are body-level invariants asserted by `AsrBodySchema`; this profile does
 * not duplicate them.
 *
 * The 30-day / +60-day deadline check (spec §5.1) is a verifier-surface
 * concern surfaced as `fulfilment_overdue` warning (§7 step 4); not
 * representable on the `ProfileValidator` boolean shape.
 */

import type { AsrBody } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const ART15_ACCESS_PROFILE_ID = "subject_rights.art15.access" as const;

export function validateArt15Access(body: AsrBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "request.fulfilled") {
    if (body.arr_receipt_id != null && body.arr_receipt_id !== "") {
      errors.push("subject_rights.art15.access.arr_receipt_id.forbidden");
    }
    if (body.portability_format != null && body.portability_format !== "") {
      errors.push("subject_rights.art15.access.portability_format.forbidden");
    }
  }

  return { errors };
}

export const validateArt15AccessProfile = makeProfileAdapter(ART15_ACCESS_PROFILE_ID, (body) => validateArt15Access(body as AsrBody));
