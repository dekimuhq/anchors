/**
 * `eidas.qeseal` profile validator — AAR spec §5.2.
 *
 * Hook: eIDAS Regulation Art 35 — Qualified Electronic Seals (legal persons).
 * A receipt bearing this profile MUST originate from a QTSP listed in a
 * national Trusted Service List for the QESeal service type.
 *
 * v1 invariants enforced here:
 *   - `body.event_type` MUST be `"issuance"` (revocation is skipped).
 *   - `body.service_type` MUST be `"qeseal"`.
 *   - `body.signature_format` MUST be a recognised ETSI baseline format.
 *   - `body.qcert_serial_commit` MUST be non-null.
 *   - `body.tsl_country` MUST be an EU/EEA member state.
 */

import type { AarBody, AarSignatureFormat } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const EIDAS_QESEAL_PROFILE_ID = "eidas.qeseal" as const;

const EU_EEA_COUNTRIES: ReadonlySet<string> = new Set([
  "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
  "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
  "PL", "PT", "RO", "SK", "SI", "ES", "SE",
  "IS", "LI", "NO",
]);

const SIGNATURE_FORMATS: ReadonlySet<AarSignatureFormat> = new Set([
  "pades_b_b", "pades_b_t", "pades_b_lt", "pades_b_lta",
  "xades_b_b", "xades_b_t", "xades_b_lt", "xades_b_lta",
  "cades_b_b", "cades_b_t", "cades_b_lt", "cades_b_lta",
  "jades_b_b", "jades_b_t", "jades_b_lt", "jades_b_lta",
]);

/**
 * Pure validator. Returns the collected `errors[]` — empty when valid.
 * Revocation events pass unconditionally (no additional QESeal constraints).
 */
export function validateEidasQeseal(body: AarBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "revocation") {
    return { errors };
  }

  if (body.service_type !== "qeseal") {
    errors.push("eidas.qeseal.service_type_mismatch");
  }

  if (body.signature_format === null || !SIGNATURE_FORMATS.has(body.signature_format)) {
    errors.push("eidas.qeseal.signature_format_invalid");
  }

  if (body.qcert_serial_commit === null) {
    errors.push("eidas.qeseal.qcert_serial_commit_missing");
  }

  if (!EU_EEA_COUNTRIES.has(body.tsl_country)) {
    errors.push("eidas.qeseal.tsl_country_not_eu_eea");
  }

  return { errors };
}

export const validateEidasQesealProfile = makeProfileAdapter(
  EIDAS_QESEAL_PROFILE_ID,
  (body) => validateEidasQeseal(body as AarBody),
);
