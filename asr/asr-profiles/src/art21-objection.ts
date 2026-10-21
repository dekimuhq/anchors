/**
 * `subject_rights.art21.objection` profile validator — ASR spec §5.6.
 *
 * Hook: GDPR Art. 21 — right to object (legitimate-interest balancing
 * test + outcome).
 *
 * v1 invariants enforced here:
 *   - On `request.fulfilled`: `body.objection_scope` MUST be one of the
 *     three closed-enum values.
 *   - On `request.fulfilled` AND `objection_scope === "art21_1_general_legitimate_interest"`:
 *     `body.balancing_test_hash` MUST be a non-empty string committing to
 *     the controller's documented re-balancing.
 *   - On `request.fulfilled`: `body.arr_receipt_id` MUST NOT be set.
 *   - On `request.fulfilled`: `body.portability_format` MUST NOT be set.
 *
 * Direct-marketing objections (`art21_1_direct_marketing`) are
 * unconditional under Art. 21(2); no balancing-test surface is required.
 *
 * Optional `body.apur_receipt_id` (spec §8.2) is not enforced here —
 * absence is not an invariant violation, presence is informational and
 * surfaced by the composition pass (Phase 3 §G).
 */

import type { AsrBody } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const ART21_OBJECTION_PROFILE_ID =
  "subject_rights.art21.objection" as const;

/** Closed enum of objection scopes (spec §5.6). */
export type Art21ObjectionScope =
  | "art21_1_direct_marketing"
  | "art21_1_general_legitimate_interest"
  | "art21_6_research";

export const ART21_OBJECTION_SCOPES: readonly Art21ObjectionScope[] = [
  "art21_1_direct_marketing",
  "art21_1_general_legitimate_interest",
  "art21_6_research",
] as const;

const ART21_SCOPE_SET: ReadonlySet<string> = new Set(ART21_OBJECTION_SCOPES);

export function validateArt21Objection(
  body: AsrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "request.fulfilled") {
    const scope = (body as { objection_scope?: unknown }).objection_scope;
    if (typeof scope !== "string" || !ART21_SCOPE_SET.has(scope)) {
      errors.push("subject_rights.art21.objection.objection_scope.invalid");
    } else if (scope === "art21_1_general_legitimate_interest") {
      const hash = (body as { balancing_test_hash?: unknown })
        .balancing_test_hash;
      if (typeof hash !== "string" || hash.length === 0) {
        errors.push(
          "subject_rights.art21.objection.balancing_test_hash.required",
        );
      }
    }
    if (body.arr_receipt_id != null && body.arr_receipt_id !== "") {
      errors.push("subject_rights.art21.objection.arr_receipt_id.forbidden");
    }
    if (body.portability_format != null && body.portability_format !== "") {
      errors.push(
        "subject_rights.art21.objection.portability_format.forbidden",
      );
    }
  }

  return { errors };
}

export const validateArt21ObjectionProfile = makeProfileAdapter(ART21_OBJECTION_PROFILE_ID, (body) => validateArt21Objection(body as AsrBody));
