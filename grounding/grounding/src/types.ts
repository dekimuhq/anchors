export type {
  GroundingProfile, ScorerMethod, SupportLevel,
  GroundingSource, GroundingCitation, GroundingClaim, Scorer,
  AGrRCaveatsConsumed, GroundingRagBody, AGrRBody,
} from "@dekimuhq/grounding-profiles";
import type { AGrRBody } from "@dekimuhq/grounding-profiles";
export interface VerifyBodyResult { valid: boolean; errors: string[]; body: AGrRBody | null; }
