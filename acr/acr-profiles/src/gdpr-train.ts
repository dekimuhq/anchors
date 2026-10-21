import type { ACRReceipt } from "./body-types.ts";
import type { ValidationResult } from "./gdpr-art7.ts";

/** GDPR lawful bases EDPB Opinion 28/2024 blesses for AI-model training. */
const ALLOWED_BASIS = new Set(["6(1)(a)", "6(1)(f)"]);
/** Training stages a consent may scope to. */
const ALLOWED_SCOPE = new Set(["pretrain", "finetune", "rlhf", "eval", "all"]);
const SHA256_HEX = /^sha256:[0-9a-f]{64}$/;
const RFC_3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/**
 * GDPR consent-to-train — GDPR Art. 6(1)(a)/(f) + EDPB Opinion 28/2024.
 *
 * `lawful_basis` is a structured triple in this profile (v1):
 *   "<basis>|<scope>|<model_commit>"
 *     basis        — "6(1)(a)" (consent) | "6(1)(f)" (legitimate interest)
 *     scope        — pretrain | finetune | rlhf | eval | all
 *     model_commit — "sha256:<64-hex>", salted commitment to the model/model-family
 *
 * Packed into the string `lawful_basis` (not a new body field) per the
 * `aiact.art14` precedent, keeping the JCS canonicalisation byte-identical.
 *
 * Honest claim: provenance of a (revocable) training-consent decision — NOT proof
 * the training pipeline honoured it. Revocation = an `ar.withdrawal.v1` ACR whose
 * `prev` is this receipt's hash, made verifiable by ACR's status list.
 */
export function validateGdprTrain(receipt: ACRReceipt): ValidationResult {
  const errors: string[] = [];

  if (receipt.profile !== "gdpr.train") {
    errors.push(`profile must be "gdpr.train", got "${receipt.profile}"`);
  }

  const parts = receipt.lawful_basis.split("|");
  if (parts.length !== 3) {
    errors.push(`lawful_basis must be "<basis>|<scope>|<model_commit>"`);
    return { valid: false, errors };
  }
  const [basis, scope, modelCommit] = parts as [string, string, string];

  if (!ALLOWED_BASIS.has(basis)) {
    errors.push(`basis must be 6(1)(a) or 6(1)(f), got "${basis}"`);
  }
  if (!ALLOWED_SCOPE.has(scope)) {
    errors.push(
      `scope must be one of pretrain|finetune|rlhf|eval|all, got "${scope}"`,
    );
  }
  if (!SHA256_HEX.test(modelCommit)) {
    errors.push(`model_commit must be sha256:<64-hex>, got "${modelCommit}"`);
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
