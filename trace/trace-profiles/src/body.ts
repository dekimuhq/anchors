/**
 * AgTR (Anchored Agent-Trace Receipts) body-type definitions. Asserts execution
 * PROVENANCE, not verified behavior. Envelope-level fields are provided by
 * @dekimuhq/anchors-envelope and NOT repeated. field_root is added issuer-side by
 * mintTraceV1. AgTRCaveatsConsumed is defined LOCALLY (do not import from action-profiles).
 */
import type { TraceProfile, TraceOutcome, TraceStage, Span } from "./types.ts";

export interface AgTRCaveatsConsumed {
  data_scope: string;
  spend_step: number;
  spend_currency?: string;
  capability: string;
}

export interface AgTRBody {
  profile: TraceProfile;
  request_id_commit: string;
  capability?: string;
  stages: TraceStage[];
  outcome: TraceOutcome;
  error_stage?: string;
  trace_commit: string;
  started_at: string;
  total_ms: number;
  policy_uri?: string;
  policy_hash?: string;
  policy_version?: string;
  credential_id?: string;
  caveats_consumed?: AgTRCaveatsConsumed;
}

/**
 * ar.trace.v2 body — signed OTel-compatible span tree. Asserts execution PROVENANCE
 * (shape + timings), not verified behavior. Envelope-level fields are provided by
 * @dekimuhq/anchors-envelope and NOT repeated. field_root is added issuer-side by
 * mintTraceV2. Per-span detail (may carry PII) lives behind spans_root, never here.
 */
export interface AgTRTreeBody {
  profile: "agent.trace";
  trace_id: string;                 // 32-hex W3C trace id
  request_id_commit: string;        // sha256:<hex> — joins to the run's AActR/AQR
  capability?: string;
  spans: Span[];                    // non-empty flat span list; tree via parent_span_id
  spans_root: string;               // sha256:<hex> Merkle root over per-span detail commits
  outcome: "ok" | "error" | "denied" | "checkpoint";
  error_span_id?: string;           // REQUIRED iff outcome === "error"
  started_at: string;               // RFC 3339 UTC
  total_ms: number;
  policy_uri?: string;
  policy_hash?: string;
  policy_version?: string;
  credential_id?: string;
  caveats_consumed?: AgTRCaveatsConsumed;
}
