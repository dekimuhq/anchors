/** Shared types for APIIR v1 (Anchored PII-Redaction Receipts). */
export type APIIRClaimType = "ar.redaction.v1";
export type RedactionProfile = "redaction.prompt";
/** Fixed category set emitted by @dekimuhq/ai redactPII. */
export type RedactionCategory = "EMAIL" | "IBAN" | "VAT" | "PHONE" | "CARD" | "CLIENT";
export type RedactionCounts = Partial<Record<RedactionCategory, number>>;
export interface ProfileValidationResult { errors: string[]; }
export const REDACTION_CATEGORIES: readonly RedactionCategory[] = [
  "EMAIL", "IBAN", "VAT", "PHONE", "CARD", "CLIENT",
];
