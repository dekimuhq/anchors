/** Shared types for AQR v1 (Anchored Quality Receipts). */
export type AQRClaimType = "ar.quality.v1";
export type AQRProfile = "quality.output" | "quality.release";
export type QualityScorerKind = "deterministic" | "llm-judge" | "human" | "hybrid";
export interface QualityScorer {
  kind: QualityScorerKind;
  /** Plaintext model id, e.g. "claude-opus-4-8". REQUIRED when kind is llm-judge | hybrid. */
  model?: string;
  model_version?: string;
}
export type QualityVerdict = "pass" | "fail" | "warn";
export interface QualityResult {
  score: number; verdict: QualityVerdict; threshold: number;
  cases_total: number; cases_passed: number;
}
export interface ProfileValidationResult { errors: string[]; }
