import { createHash } from "node:crypto";
import { lexicalOverlap, supportFor, SCORER_NAME, SCORER_VERSION, DEFAULT_THRESHOLD } from "./score.ts";
import type { CheckInput, GroundingResult, ResultCitation } from "./types.ts";

const sha256 = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

export function check(input: CheckInput): GroundingResult {
  const threshold = input.threshold ?? DEFAULT_THRESHOLD;
  if (threshold < 0 || threshold > 1) throw new Error("check: threshold must be in [0,1]");
  if (input.sources.length === 0) throw new Error("check: at least one source required");
  if (input.claims.length === 0) throw new Error("check: at least one claim required");

  const sourceById = new Map(input.sources.map((s) => [s.source_id, s]));
  const claimById = new Map(input.claims.map((c) => [c.claim_id, c]));
  if (sourceById.size !== input.sources.length) throw new Error("check: duplicate source_id");
  if (claimById.size !== input.claims.length) throw new Error("check: duplicate claim_id");

  const citations: ResultCitation[] = input.citations.map((cit) => {
    const src = sourceById.get(cit.source_id);
    if (!src) throw new Error(`check: unknown source_id ${cit.source_id}`);
    const claim = claimById.get(cit.claim_id);
    if (!claim) throw new Error(`check: unknown claim_id ${cit.claim_id}`);
    if (!Number.isInteger(cit.start) || !Number.isInteger(cit.end) || cit.start < 0) {
      throw new Error("check: start/end must be non-negative integers");
    }
    if (cit.end <= cit.start) throw new Error("check: end must be > start");
    if (cit.end > src.text.length) throw new Error(`check: span out of bounds for ${cit.source_id}`);
    const span = src.text.slice(cit.start, cit.end);
    const score = lexicalOverlap(claim.text, span);
    return {
      claim_id: cit.claim_id, source_id: cit.source_id, start: cit.start, end: cit.end,
      span_commit: sha256(span), support: supportFor(score, threshold), score,
    };
  });

  const citedClaims = new Set(citations.map((c) => c.claim_id));
  const coverage = citedClaims.size / input.claims.length;
  const supportedClaims = new Set(citations.filter((c) => c.support === "supported").map((c) => c.claim_id));
  const grounded_count = supportedClaims.size;

  return {
    answer_commit: sha256(input.answer),
    sources: input.sources.map((s) => ({
      source_id: s.source_id, source_commit: sha256(s.text),
      ...(s.media_type !== undefined ? { media_type: s.media_type } : {}),
    })),
    claims: input.claims.map((c) => ({ claim_id: c.claim_id, claim_commit: sha256(c.text) })),
    citations,
    coverage,
    grounded_count,
    scorer: { method: "lexical_overlap", name: SCORER_NAME, version: SCORER_VERSION, threshold },
  };
}
