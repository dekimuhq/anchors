/**
 * `subject_rights.art18.restriction` profile validator — ASR spec §5.4.
 *
 * Hook: GDPR Art. 18 — right to restriction of processing.
 *
 * v1 invariants enforced here:
 *   - On `request.fulfilled`: `body.restriction_reason_code` MUST be one of
 *     the four Art. 18(1)(a)–(d) closed-enum values.
 *   - On `request.fulfilled`: `body.arr_receipt_id` MUST NOT be set.
 *   - On `request.fulfilled`: `body.portability_format` MUST NOT be set.
 *
 * The durative nature of restriction (data locked but retained) is a
 * controller-state concern; subsequent Art. 15 responses enumerate the
 * ongoing restriction. ASR anchors the request, not the persistent state.
 */

import type { AsrBody } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const ART18_RESTRICTION_PROFILE_ID =
  "subject_rights.art18.restriction" as const;

/** Art. 18(1)(a)–(d) closed enum (spec §5.4). */
export type Art18RestrictionReason =
  | "art18_1_a_accuracy_contested"
  | "art18_1_b_unlawful_processing"
  | "art18_1_c_controller_no_longer_needs"
  | "art18_1_d_objection_pending";

export const ART18_RESTRICTION_REASONS: readonly Art18RestrictionReason[] = [
  "art18_1_a_accuracy_contested",
  "art18_1_b_unlawful_processing",
  "art18_1_c_controller_no_longer_needs",
  "art18_1_d_objection_pending",
] as const;

const ART18_REASON_SET: ReadonlySet<string> = new Set(ART18_RESTRICTION_REASONS);

export function validateArt18Restriction(
  body: AsrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "request.fulfilled") {
    const reason = (body as { restriction_reason_code?: unknown })
      .restriction_reason_code;
    if (typeof reason !== "string" || !ART18_REASON_SET.has(reason)) {
      errors.push(
        "subject_rights.art18.restriction.restriction_reason_code.invalid",
      );
    }
    if (body.arr_receipt_id != null && body.arr_receipt_id !== "") {
      errors.push("subject_rights.art18.restriction.arr_receipt_id.forbidden");
    }
    if (body.portability_format != null && body.portability_format !== "") {
      errors.push(
        "subject_rights.art18.restriction.portability_format.forbidden",
      );
    }
  }

  return { errors };
}

export const validateArt18RestrictionProfile = makeProfileAdapter(ART18_RESTRICTION_PROFILE_ID, (body) => validateArt18Restriction(body as AsrBody));
