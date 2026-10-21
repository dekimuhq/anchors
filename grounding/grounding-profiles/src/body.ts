/**
 * AGrR (Anchored Grounding Receipts) body definitions.
 * Asserts citation-binding PROVENANCE, not truth. Envelope-level fields come
 * from @dekimuhq/anchors-envelope and are NOT repeated. field_root is added
 * issuer-side by mintGroundingV1.
 */
export const GROUNDING_PROFILES = ["grounding.rag"] as const;
export type { GroundingProfile, ScorerMethod, SupportLevel, GroundingSource, GroundingCitation, GroundingClaim, Scorer, AGrRCaveatsConsumed, GroundingRagBody, AGrRBody } from "./types.ts";
