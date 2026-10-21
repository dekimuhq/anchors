import { tokenize } from "./tokenize.ts";

export const SCORER_NAME = "dekimu/grounding-check";
export const SCORER_VERSION = "1.0.0";
export const DEFAULT_THRESHOLD = 0.6;

export type SupportLevel = "supported" | "partial" | "unsupported";

/** Fraction of the claim's (distinct) tokens that appear in the span. Empty claim → 0. */
export function lexicalOverlap(claim: string, span: string): number {
  const claimToks = [...new Set(tokenize(claim))];
  if (claimToks.length === 0) return 0;
  const spanToks = new Set(tokenize(span));
  let hit = 0;
  for (const t of claimToks) if (spanToks.has(t)) hit++;
  return hit / claimToks.length;
}

/** Ordered mapping — resolves the threshold===0 edge deterministically. */
export function supportFor(score: number, threshold: number): SupportLevel {
  if (score === 0) return "unsupported";
  if (score >= threshold) return "supported";
  return "partial";
}
