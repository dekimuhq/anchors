import type { ACRReceipt } from "./body-types.ts";
import type { ValidationResult } from "./gdpr-art7.ts";

const ALLOWED_ACTIONS = new Set(["approved", "rejected", "escalated", "overridden"]);
const SHA256_HEX = /^sha256:[0-9a-f]{64}$/;

/**
 * AI Act Article 14 — human oversight attestation.
 *
 * `lawful_basis` is a structured triple in this profile (v1):
 *   "<action>|<apr_receipt_hash>|<reviewer_role_commit>"
 *
 * Future profile revisions MAY introduce a dedicated structured field
 * once the spec adds JSON object support there; v1 stays string-only
 * to keep the canonicalisation contract identical to gdpr.art7.
 */
export function validateAiActArt14(receipt: ACRReceipt): ValidationResult {
  const errors: string[] = [];

  if (receipt.profile !== "aiact.art14") {
    errors.push(`profile must be "aiact.art14", got "${receipt.profile}"`);
  }

  const parts = receipt.lawful_basis.split("|");
  if (parts.length !== 3) {
    errors.push(
      `lawful_basis must be "<action>|<apr_receipt_hash>|<reviewer_role_commit>"`,
    );
    return { valid: false, errors };
  }
  const [action, aprHash, roleCommit] = parts as [string, string, string];

  if (!ALLOWED_ACTIONS.has(action)) {
    errors.push(
      `oversight_action must be one of approved|rejected|escalated|overridden, got "${action}"`,
    );
  }
  if (!SHA256_HEX.test(aprHash)) {
    errors.push(`apr_receipt_hash must be sha256:<64-hex>, got "${aprHash}"`);
  }
  if (!SHA256_HEX.test(roleCommit)) {
    errors.push(`reviewer_role_commit must be sha256:<64-hex>, got "${roleCommit}"`);
  }

  return { valid: errors.length === 0, errors };
}
