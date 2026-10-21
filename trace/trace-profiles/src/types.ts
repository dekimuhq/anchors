/** Shared types for AgTR v1 (Anchored Agent-Trace Receipts). */
export type TraceClaimType = "ar.trace.v1";
export type TraceProfile = "agent.trace";
export type TraceOutcome = "ok" | "error" | "denied" | "checkpoint";
export type TraceStageStatus = "ok" | "error" | "skipped";

export interface TraceStage {
  /** Fixed plaintext pipeline label, e.g. "validate" | "oversight" | "execute". Non-PII. */
  stage: string;
  /** Stage duration in ms — non-negative integer. */
  ms: number;
  status: TraceStageStatus;
}

export interface ProfileValidationResult { errors: string[]; }

/** ar.trace.v2 — OTel span data model. Tree is expressed by parent_span_id pointers, not nesting. */
export type TraceClaimTypeV2 = "ar.trace.v2";
export type SpanStatus = "unset" | "ok" | "error";

export interface Span {
  /** 16-hex (8 bytes) lowercase, unique within the trace. */
  span_id: string;
  /** null for a root span; else references another span_id in this trace. */
  parent_span_id: string | null;
  /** Plaintext span name — fixed machinery label, non-PII (e.g. "stage.execute", "llm.call"). */
  name: string;
  /** Integer ms offset from the run's started_at (relative → clock-independent). */
  start_offset_ms: number;
  /** Integer ms span duration. */
  duration_ms: number;
  status: SpanStatus;
}
