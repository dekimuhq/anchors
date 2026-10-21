/**
 * `subject_rights.art17.erasure_request` profile validator — ASR spec §5.3.
 *
 * Hook: GDPR Art. 17 — right to erasure (request lifecycle only; execution
 * stays in ARR).
 *
 * v1 invariants enforced here:
 *   - On `request.fulfilled`: `body.arr_receipt_id` MUST be a non-empty
 *     string (D10-ASR-3 MANDATORY cross-link to the ARR `ar.erasure.v1` or
 *     `ar.anonymization.v1` receipt). Absence → `art17_arr_link_missing`.
 *   - On `request.fulfilled`: `body.portability_format` MUST NOT be set.
 *
 * Stale-link checks (±14 days), subject-parity (`ARR.body.target_commit ===
 * ASR.subject`), and ARR `claim_type` enforcement are cross-family
 * composition concerns deferred to Phase 3 §G `compose`. The profile-level
 * rejection codes there will be `art17_arr_stale_link`,
 * `art17_arr_subject_mismatch`, `art17_arr_wrong_claim_type` (spec §5.3 +
 * D10-ASR-3).
 */

import type { AsrBody } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const ART17_ERASURE_REQUEST_PROFILE_ID =
  "subject_rights.art17.erasure_request" as const;

export function validateArt17ErasureRequest(
  body: AsrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "request.fulfilled") {
    if (
      typeof body.arr_receipt_id !== "string" ||
      body.arr_receipt_id.length === 0
    ) {
      errors.push("subject_rights.art17.erasure_request.arr_receipt_id.missing");
    }
    if (body.portability_format != null && body.portability_format !== "") {
      errors.push(
        "subject_rights.art17.erasure_request.portability_format.forbidden",
      );
    }
  }

  return { errors };
}

export const validateArt17ErasureRequestProfile = makeProfileAdapter(ART17_ERASURE_REQUEST_PROFILE_ID, (body) => validateArt17ErasureRequest(body as AsrBody));
