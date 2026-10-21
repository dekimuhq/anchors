/**
 * `eidas.qts` profile validator — AAR spec §5.3.
 *
 * Hook: eIDAS Regulation Art 42 — Qualified (Electronic) Time Stamps.
 * A receipt bearing this profile MUST originate from a QTSP listed in a
 * national Trusted Service List for the QTS service type.
 *
 * v1 invariants enforced here:
 *   - `body.event_type` MUST be `"issuance"` (revocation is skipped).
 *   - `body.service_type` MUST be `"qts"`.
 *   - `body.qcert_serial_commit` MUST be non-null (timestamps carry a TSA cert).
 *   - `body.tsl_country` MUST be an EU/EEA member state.
 *
 * `signature_format` is NOT checked: QTS eIDAS Art 42 does not prescribe
 * a specific ETSI baseline container format at this profile level.
 */

import type { AarBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const EIDAS_QTS_PROFILE_ID = "eidas.qts" as const;

const EU_EEA_COUNTRIES: ReadonlySet<string> = new Set([
  "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
  "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
  "PL", "PT", "RO", "SK", "SI", "ES", "SE",
  "IS", "LI", "NO",
]);

/**
 * Pure validator. Returns the collected `errors[]` — empty when valid.
 * Revocation events pass unconditionally (no additional QTS constraints).
 */
export function validateEidasQts(body: AarBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "revocation") {
    return { errors };
  }

  if (body.service_type !== "qts") {
    errors.push("eidas.qts.service_type_mismatch");
  }

  if (body.qcert_serial_commit === null) {
    errors.push("eidas.qts.qcert_serial_commit_missing");
  }

  if (!EU_EEA_COUNTRIES.has(body.tsl_country)) {
    errors.push("eidas.qts.tsl_country_not_eu_eea");
  }

  return { errors };
}

export const validateEidasQtsProfile = makeProfileAdapter(
  EIDAS_QTS_PROFILE_ID,
  (body) => validateEidasQts(body as AarBody),
);
