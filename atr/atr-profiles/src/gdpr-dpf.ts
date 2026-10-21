/**
 * `gdpr.dpf` profile validator — ATR spec §5.7.
 *
 * Hook: EU-U.S. Data Privacy Framework (July 2023 adequacy decision). On
 * `arrangement` events the receipt MUST name the DPF version.
 *
 * v1 invariants enforced here:
 *   - On `arrangement` events: `body.mechanism_version` MUST be `dpf-2023`.
 *   - All other event types: pass through (no errors).
 */

import type { AtrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_DPF_PROFILE_ID = "gdpr.dpf" as const;

export function validateGdprDpf(body: AtrBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "arrangement") {
    return { errors };
  }

  if (body.mechanism_version !== "dpf-2023") {
    errors.push("gdpr.dpf.mechanism_version_invalid");
  }

  return { errors };
}

export const validateGdprDpfProfile = makeProfileAdapter(
  GDPR_DPF_PROFILE_ID,
  (body) => validateGdprDpf(body as AtrBody),
);
