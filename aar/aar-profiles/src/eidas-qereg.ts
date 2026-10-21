/**
 * `eidas.qereg` profile validator — AAR spec §5.4.
 *
 * Hook: eIDAS Regulation Art 44 — Qualified Electronic Registered Delivery
 * Services (QERDS). A receipt bearing this profile MUST originate from a QTSP
 * listed in a national Trusted Service List for the QERDS service type.
 *
 * v1 invariants enforced here:
 *   - `body.event_type` MUST be `"issuance"` (revocation is skipped).
 *   - `body.service_type` MUST be `"qereg"`.
 *   - `body.artefact_hash` MUST be non-null (QERDS receipts MUST reference the
 *     delivered artefact by content hash).
 *   - `body.tsl_country` MUST be an EU/EEA member state.
 */

import type { AarBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const EIDAS_QEREG_PROFILE_ID = "eidas.qereg" as const;

const EU_EEA_COUNTRIES: ReadonlySet<string> = new Set([
  "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
  "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
  "PL", "PT", "RO", "SK", "SI", "ES", "SE",
  "IS", "LI", "NO",
]);

/**
 * Pure validator. Returns the collected `errors[]` — empty when valid.
 * Revocation events pass unconditionally (no additional QERDS constraints).
 */
export function validateEidasQereg(body: AarBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "revocation") {
    return { errors };
  }

  if (body.service_type !== "qereg") {
    errors.push("eidas.qereg.service_type_mismatch");
  }

  if (body.artefact_hash === null) {
    errors.push("eidas.qereg.artefact_hash_required");
  }

  if (!EU_EEA_COUNTRIES.has(body.tsl_country)) {
    errors.push("eidas.qereg.tsl_country_not_eu_eea");
  }

  return { errors };
}

export const validateEidasQeregProfile = makeProfileAdapter(
  EIDAS_QEREG_PROFILE_ID,
  (body) => validateEidasQereg(body as AarBody),
);
