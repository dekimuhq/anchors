export type {
  AGRProfile, GuardMatch, GuardDetector, GuardDecision,
  GuardInputBody, AGRBody, AGRCaveatsConsumed,
} from "@dekimuhq/guard-profiles";
import type { AGRBody } from "@dekimuhq/guard-profiles";
export interface VerifyBodyResult { valid: boolean; errors: string[]; body: AGRBody | null; }
