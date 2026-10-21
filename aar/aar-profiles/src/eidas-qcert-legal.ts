/**
 * `eidas.qcert.legal` profile validator — AAR spec §5.6.
 *
 * Hook: eIDAS Regulation — Qualified Certificates for legal persons
 * (non-signing — i.e. certificate issuance receipts, not QESeal signing
 * receipts). A receipt bearing this profile MUST originate from a QTSP issuing
 * a QC to a legal person, listed in a national Trusted Service List.
 *
 * v1 invariants enforced here:
 *   - `body.event_type` MUST be `"issuance"` (revocation is skipped).
 *   - `body.service_type` MUST be `"qcert_legal"`.
 *   - `body.qcert_serial_commit` MUST be non-null.
 *   - `body.signature_format` MUST be null (certificate issuance is not a
 *     signed-document event).
 *   - `body.tsl_country` MUST be an EU/EEA member state.
 */

import type { AarBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const EIDAS_QCERT_LEGAL_PROFILE_ID = "eidas.qcert.legal" as const;

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
export function validateEidasQcertLegal(body: AarBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type === "revocation") {
    return { errors };
  }

  if (body.service_type !== "qcert_legal") {
    errors.push("eidas.qcert.legal.service_type_mismatch");
  }

  if (body.qcert_serial_commit === null) {
    errors.push("eidas.qcert.legal.qcert_serial_commit_missing");
  }

  if (body.signature_format !== null) {
    errors.push("eidas.qcert.legal.signature_format_must_be_null");
  }

  if (!EU_EEA_COUNTRIES.has(body.tsl_country)) {
    errors.push("eidas.qcert.legal.tsl_country_not_eu_eea");
  }

  return { errors };
}

export const validateEidasQcertLegalProfile = makeProfileAdapter(
  EIDAS_QCERT_LEGAL_PROFILE_ID,
  (body) => validateEidasQcertLegal(body as AarBody),
);
