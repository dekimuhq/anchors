/** `agent.trace` v2 (span-tree) advisory validator — spec §6 (advisory surface). */
import type { AgTRTreeBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AGENT_TRACE_TREE_PROFILE_ID = "agent.trace" as const;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const TRACE_ID_RE = /^[0-9a-f]{32}$/;
const SPAN_ID_RE = /^[0-9a-f]{16}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const OUTCOMES = new Set(["ok", "error", "denied", "checkpoint"]);
const SPAN_STATUS = new Set(["unset", "ok", "error"]);
const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isInt0 = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0;

export function validateAgentTraceTree(body: AgTRTreeBody): ProfileValidationResult {
  const b = body as unknown as Record<string, unknown>;
  const errors: string[] = [];
  if (b.profile !== "agent.trace") errors.push("trace.wrong_profile");
  if (typeof b.trace_id !== "string" || !TRACE_ID_RE.test(b.trace_id)) errors.push("trace.trace_id_malformed");
  if (typeof b.request_id_commit !== "string" || !SHA256_RE.test(b.request_id_commit)) errors.push("trace.request_id_commit_malformed");
  const ids = new Set<string>();
  if (!Array.isArray(b.spans) || b.spans.length === 0) {
    errors.push("trace.spans_empty");
  } else {
    for (const s of b.spans) {
      const sp = s as Record<string, unknown>;
      if (typeof sp.span_id === "string" && SPAN_ID_RE.test(sp.span_id)) ids.add(sp.span_id);
    }
    let roots = 0;
    b.spans.forEach((s, i) => {
      const sp = s as Record<string, unknown>;
      if (typeof sp.span_id !== "string" || !SPAN_ID_RE.test(sp.span_id)) errors.push(`trace.spans.${i}.span_id_invalid`);
      if (sp.parent_span_id === null) roots++;
      else if (typeof sp.parent_span_id !== "string" || !ids.has(sp.parent_span_id)) errors.push(`trace.spans.${i}.parent_unresolved`);
      if (!isStr(sp.name)) errors.push(`trace.spans.${i}.name_invalid`);
      if (!isInt0(sp.start_offset_ms)) errors.push(`trace.spans.${i}.start_offset_invalid`);
      if (!isInt0(sp.duration_ms)) errors.push(`trace.spans.${i}.duration_invalid`);
      if (typeof sp.status !== "string" || !SPAN_STATUS.has(sp.status)) errors.push(`trace.spans.${i}.status_invalid`);
    });
    if (roots === 0) errors.push("trace.no_root");
  }
  if (typeof b.spans_root !== "string" || !SHA256_RE.test(b.spans_root)) errors.push("trace.spans_root_malformed");
  if (typeof b.outcome !== "string" || !OUTCOMES.has(b.outcome)) errors.push("trace.outcome_invalid");
  if (b.outcome === "error" && !isStr(b.error_span_id)) errors.push("trace.error_span_missing");
  if (b.error_span_id !== undefined && (!isStr(b.error_span_id) || !ids.has(b.error_span_id))) errors.push("trace.error_span_unresolved");
  if (!isStr(b.started_at) || !RFC3339_RE.test(b.started_at as string) || Number.isNaN(Date.parse(b.started_at as string))) errors.push("trace.started_at_invalid");
  if (!isInt0(b.total_ms)) errors.push("trace.total_ms_invalid");
  if (b.policy_hash !== undefined && (typeof b.policy_hash !== "string" || !SHA256_RE.test(b.policy_hash))) errors.push("trace.policy_hash_malformed");
  if (b.credential_id !== undefined && !isStr(b.credential_id)) errors.push("trace.credential_id_invalid");
  if (b.caveats_consumed !== undefined && b.credential_id === undefined) errors.push("trace.caveats_orphan");
  return { errors };
}

export const validateAgentTraceTreeProfile = makeProfileAdapter(
  AGENT_TRACE_TREE_PROFILE_ID, (body) => validateAgentTraceTree(body as AgTRTreeBody),
);
