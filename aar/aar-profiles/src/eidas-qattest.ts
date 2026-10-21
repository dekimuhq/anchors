/**
 * `eidas.qattest` profile validator — AAR spec §5.8.
 *
 * Hook: eIDAS 2.0 — Qualified Attestation of Attributes. A receipt bearing
 * this profile MUST originate from a provider listed in a national Trusted
 * Service List for the Qualified Attestation of Attributes service type.
 *
 * v1 invariants enforced here:
 *   - `body.event_type` MUST be `"issuance"` (revocation is skipped).
 *   - `body.service_type` MUST be `"qattest"`.
 *
 * Additional structural fields are validated at the envelope level. This
 * profile only gates on service_type conformance for v1.
 */

import type { AarBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const EIDAS_QATTEST_PROFILE_ID = "eidas.qattest" as const;

/**
 * Pure validator. Returns the collected `errors[]` — empty when valid.
 * Revocation events pass unconditionally (no additional QAttest constraints).
 */
export function validateEidasQattest(body: AarBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "revocation") {
    return { errors };
  }

  if (body.service_type !== "qattest") {
    errors.push("eidas.qattest.service_type_mismatch");
  }

  return { errors };
}

export const validateEidasQattestProfile = makeProfileAdapter(
  EIDAS_QATTEST_PROFILE_ID,
  (body) => validateEidasQattest(body as AarBody),
);
