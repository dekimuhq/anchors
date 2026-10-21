/**
 * `purpose.lgpd.art6` profile validator — APuR spec §5.5.
 *
 * Hook: LGPD Art 6 — adequação à finalidade (purpose adequacy). Applies to
 * binding events only.
 *
 * v1 invariants enforced here:
 *   - Event type must be "binding" — others are rejected.
 *   - `purpose_class` must be namespaced under "lgpd:".
 */

import type { ApurBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const LGPD_ART6_PROFILE_ID = "purpose.lgpd.art6" as const;

export function validateLgpdArt6(body: ApurBody): ProfileValidationResult {
  const errors: string[] = [];

  const b = body as unknown as Record<string, unknown>;

  if (b["event_type"] !== "binding") {
    errors.push("purpose.lgpd.art6.wrong_event_type");
    return { errors };
  }

  const purposeClass = b["purpose_class"];
  if (
    typeof purposeClass !== "string" ||
    !purposeClass.startsWith("lgpd:")
  ) {
    errors.push("purpose.lgpd.art6.purpose_class_namespace");
  }

  return { errors };
}

export const validateLgpdArt6Profile = makeProfileAdapter(
  LGPD_ART6_PROFILE_ID,
  (body) => validateLgpdArt6(body as ApurBody),
);
