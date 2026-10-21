/** AGrR (Anchored Grounding Receipts) body types — verbatim from spec §3. */

export type GroundingProfile = "grounding.rag";
export type ScorerMethod = "lexical_overlap"; // v1 locked; additive: "nli" | "llm_judge"
export type SupportLevel = "supported" | "partial" | "unsupported";

export interface GroundingSource {
  source_id: string;        // stable id referenced by citations, e.g. "doc-1#para-4"
  source_commit: string;    // sha-256 of the full source document (lowercase hex, 64)
  media_type?: string;      // e.g. "text/plain"
}

export interface GroundingCitation {
  claim_id: string;         // stable id of the claim within the answer
  source_id: string;        // MUST match a sources[].source_id
  start: number;            // span start offset (reference-engine string code units = JS UTF-16, inclusive; spec §3 "Offset units")
  end: number;              // span end offset (exclusive); end > start
  span_commit: string;      // sha-256 of source[start:end] — the binding-integrity anchor
  support: SupportLevel;    // scorer verdict for THIS citation (method below)
  score: number;            // 0..1 support score from the named scorer method
}

export interface GroundingClaim {
  claim_id: string;         // stable id; referenced by citations
  claim_commit: string;     // sha-256 of the claim text (commitment, never the text)
}

export interface Scorer {
  method: ScorerMethod;     // "lexical_overlap" in v1
  name: string;             // e.g. "dekimu/grounding-check"
  version: string;          // scorer implementation semver
  threshold: number;        // 0..1 — support cutoff (ordered mapping, §3); part of scorer identity
}

export interface AGrRCaveatsConsumed {  // optional Mandate binding — same shape family as AQR/AGR
  data_scope: string;
  spend_step: number;
  spend_currency?: string;
  capability: string;
}

export interface GroundingRagBody {
  profile: "grounding.rag";
  answer_commit: string;        // sha-256 of the full answer text
  sources: GroundingSource[];   // ≥1; unique source_id
  claims: GroundingClaim[];     // ≥1; unique claim_id
  citations: GroundingCitation[]; // 0..n; each references a claim_id + source_id present above
  coverage: number;             // 0..1 — |claims with ≥1 citation| / |claims| (deterministic)
  grounded_count: number;       // # claims with ≥1 citation whose support === "supported"
  scorer: Scorer;
  scored_at: string;            // RFC 3339
  answer_media_type?: string;   // e.g. "text/markdown"
  credential_id?: string;       // optional Mandate credential binding
  caveats_consumed?: AGrRCaveatsConsumed;
}

export type AGrRBody = GroundingRagBody;  // single profile in v1; union-ready
