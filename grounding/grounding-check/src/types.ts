import type { SupportLevel } from "./score.ts";
export type { SupportLevel };

export interface CheckSource { source_id: string; text: string; media_type?: string; }
export interface CheckClaim { claim_id: string; text: string; }
export interface CheckCitation { claim_id: string; source_id: string; start: number; end: number; }

export interface CheckInput {
  answer: string;
  sources: CheckSource[];
  claims: CheckClaim[];
  citations: CheckCitation[];
  threshold?: number; // defaults to DEFAULT_THRESHOLD
}

export interface ResultSource { source_id: string; source_commit: string; media_type?: string; }
export interface ResultClaim { claim_id: string; claim_commit: string; }
export interface ResultCitation {
  claim_id: string; source_id: string; start: number; end: number;
  span_commit: string; support: SupportLevel; score: number;
}
export interface Scorer { method: "lexical_overlap"; name: string; version: string; threshold: number; }

export interface GroundingResult {
  answer_commit: string;
  sources: ResultSource[];
  claims: ResultClaim[];
  citations: ResultCitation[];
  coverage: number;
  grounded_count: number;
  scorer: Scorer;
}
