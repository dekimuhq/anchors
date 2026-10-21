export type {
  AgTRBody, AgTRCaveatsConsumed,
  TraceProfile, TraceClaimType, TraceOutcome, TraceStage, TraceStageStatus,
} from "@dekimuhq/trace-profiles";
import type { AgTRBody } from "@dekimuhq/trace-profiles";
export interface VerifyBodyResult { valid: boolean; errors: string[]; body: AgTRBody | null; }
export type { AgTRTreeBody, Span, SpanStatus } from "@dekimuhq/trace-profiles";
