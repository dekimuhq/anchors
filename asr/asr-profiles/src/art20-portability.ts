/**
 * `subject_rights.art20.portability` profile validator — ASR spec §5.5.
 *
 * Hook: GDPR Art. 20 — right to data portability.
 *
 * v1 invariants enforced here:
 *   - On `request.fulfilled`: `body.portability_format` MUST be one of the
 *     closed-enum format codes.
 *   - On `request.fulfilled`: when `body.portability_format === "other"`,
 *     `body.portability_format_detail` MUST be a non-empty string.
 *   - On `request.fulfilled`: `body.arr_receipt_id` MUST NOT be set
 *     (Art. 17 erasure cross-link).
 *
 * Cross-border ATR cross-link (`body.atr_receipt_id`, spec §8.3) is
 * OPTIONAL and not enforced here; absence surfaces an
 * `art20_cross_border_atr_missing` informational warning from the verifier's
 * composition surface (Phase 3 §G).
 *
 * `body.portability_recipient_did` shape (did:web in v1) is not validated
 * here — the verifier-side composition surface handles cross-controller
 * resolution.
 */

import type { AsrBody } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const ART20_PORTABILITY_PROFILE_ID =
  "subject_rights.art20.portability" as const;

/** Closed enum of accepted portability formats (spec §5.5). */
export type Art20PortabilityFormat =
  | "json"
  | "csv"
  | "xml"
  | "fhir"
  | "dkim_signed_jwt_bundle"
  | "parquet"
  | "other";

export const ART20_PORTABILITY_FORMATS: readonly Art20PortabilityFormat[] = [
  "json",
  "csv",
  "xml",
  "fhir",
  "dkim_signed_jwt_bundle",
  "parquet",
  "other",
] as const;

const ART20_FORMAT_SET: ReadonlySet<string> = new Set(ART20_PORTABILITY_FORMATS);

export function validateArt20Portability(
  body: AsrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "request.fulfilled") {
    const format = body.portability_format;
    if (typeof format !== "string" || !ART20_FORMAT_SET.has(format)) {
      errors.push(
        "subject_rights.art20.portability.portability_format.invalid",
      );
    } else if (format === "other") {
      const detail = (body as { portability_format_detail?: unknown })
        .portability_format_detail;
      if (typeof detail !== "string" || detail.length === 0) {
        errors.push(
          "subject_rights.art20.portability.portability_format_detail.required",
        );
      }
    }
    if (body.arr_receipt_id != null && body.arr_receipt_id !== "") {
      errors.push("subject_rights.art20.portability.arr_receipt_id.forbidden");
    }
  }

  return { errors };
}

export const validateArt20PortabilityProfile = makeProfileAdapter(ART20_PORTABILITY_PROFILE_ID, (body) => validateArt20Portability(body as AsrBody));
