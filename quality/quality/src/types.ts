export type {
  AQRBody, AQROutputBody, AQRReleaseBody, AQRCaveatsConsumed,
  AQRProfile, AQRClaimType, QualityScorer, QualityResult, QualityVerdict,
} from "@dekimuhq/quality-profiles";
import type { AQRBody } from "@dekimuhq/quality-profiles";
export interface VerifyBodyResult { valid: boolean; errors: string[]; body: AQRBody | null; }
