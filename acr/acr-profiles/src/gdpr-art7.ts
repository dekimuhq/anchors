import type { ACRReceipt } from "./body-types.ts";

const ALLOWED_LAWFUL_BASIS = new Set([
  "6(1)(a)", // consent
  "6(1)(b)", // contract
  "6(1)(c)", // legal obligation
  "6(1)(d)", // vital interests
  "6(1)(e)", // public task
  "6(1)(f)", // legitimate interests
]);

// Very basic RFC 3339 sniff. Verifiers SHOULD cross-check anyway.
const RFC_3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateGdprArt7(receipt: ACRReceipt): ValidationResult {
  const errors: string[] = [];

  if (receipt.profile !== "gdpr.art7") {
    errors.push(`profile must be "gdpr.art7", got "${receipt.profile}"`);
  }
  if (!ALLOWED_LAWFUL_BASIS.has(receipt.lawful_basis)) {
    errors.push(
      `lawful_basis must be one of 6(1)(a)..6(1)(f), got "${receipt.lawful_basis}"`,
    );
  }
  if (receipt.purposes.length === 0) {
    errors.push("purposes must contain at least one commitment");
  }
  if (!RFC_3339_UTC.test(receipt.granted_at)) {
    errors.push(`granted_at must be RFC 3339 UTC, got "${receipt.granted_at}"`);
  }
  if (receipt.expires_at !== undefined && !RFC_3339_UTC.test(receipt.expires_at)) {
    errors.push(`expires_at must be RFC 3339 UTC if present, got "${receipt.expires_at}"`);
  }

  return { valid: errors.length === 0, errors };
}
