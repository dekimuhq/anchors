/**
 * `eidas.qcert.natural` profile validator — AAR spec §5.5.
 *
 * Hook: eIDAS Regulation — Qualified Certificates for natural persons
 * (non-signing — i.e. certificate issuance receipts, not QES signing receipts).
 * A receipt bearing this profile MUST originate from a QTSP issuing a QC to a
 * natural person, listed in a national Trusted Service List.
 *
 * v1 invariants enforced here:
 *   - `body.event_type` MUST be `"issuance"` (revocation is skipped).
 *   - `body.service_type` MUST be `"qcert_natural"`.
 *   - `body.qcert_serial_commit` MUST be non-null (the certificate serial must
 *     be committed).
 *   - `body.signature_format` MUST be null (certificate issuance is not a
 *     signed-document event — no container format applies).
 *   - `body.tsl_country` MUST be an EU/EEA member state.
 */

import type { AarBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const EIDAS_QCERT_NATURAL_PROFILE_ID = "eidas.qcert.natural" as const;

const EU_EEA_COUNTRIES: ReadonlySet<string> = new Set([
  "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
  "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
  "PL", "PT", "RO", "SK", "SI", "ES", "SE",
  "IS", "LI", "NO",
]);

/**
 * Pure validator. Returns the collected `errors[]` — empty when valid.
 * Revocation events pass unconditionally (no additional QC constraints).
 */
export function validateEidasQcertNatural(body: AarBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "revocation") {
    return { errors };
  }

  if (body.service_type !== "qcert_natural") {
    errors.push("eidas.qcert.natural.service_type_mismatch");
  }

  if (body.qcert_serial_commit === null) {
    errors.push("eidas.qcert.natural.qcert_serial_commit_missing");
  }

  if (body.signature_format !== null) {
    errors.push("eidas.qcert.natural.signature_format_must_be_null");
  }

  if (!EU_EEA_COUNTRIES.has(body.tsl_country)) {
    errors.push("eidas.qcert.natural.tsl_country_not_eu_eea");
  }

  return { errors };
}

export const validateEidasQcertNaturalProfile = makeProfileAdapter(
  EIDAS_QCERT_NATURAL_PROFILE_ID,
  (body) => validateEidasQcertNatural(body as AarBody),
);
