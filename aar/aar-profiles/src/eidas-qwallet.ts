/**
 * `eidas.qwallet` profile validator — AAR spec §5.7.
 *
 * Hook: eIDAS 2.0 — European Digital Identity (EUDI) Wallet. A receipt bearing
 * this profile MUST originate from a wallet provider listed in a national
 * Trusted Service List for the Qualified Wallet service type.
 *
 * v1 invariants enforced here:
 *   - `body.event_type` MUST be `"issuance"` (revocation is skipped).
 *   - `body.service_type` MUST be `"qwallet"`.
 *
 * Additional structural fields (artefact_hash, tsl_country, etc.) are
 * validated at the envelope level. This profile only gates on service_type
 * conformance for v1.
 */

import type { AarBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const EIDAS_QWALLET_PROFILE_ID = "eidas.qwallet" as const;

/**
 * Pure validator. Returns the collected `errors[]` — empty when valid.
 * Revocation events pass unconditionally (no additional QWallet constraints).
 */
export function validateEidasQwallet(body: AarBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "revocation") {
    return { errors };
  }

  if (body.service_type !== "qwallet") {
    errors.push("eidas.qwallet.service_type_mismatch");
  }

  return { errors };
}

export const validateEidasQwalletProfile = makeProfileAdapter(
  EIDAS_QWALLET_PROFILE_ID,
  (body) => validateEidasQwallet(body as AarBody),
);
