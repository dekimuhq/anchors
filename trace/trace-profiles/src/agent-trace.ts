/** `agent.trace` profile validator — AgTR spec §5 (advisory surface). */
import type { AgTRBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AGENT_TRACE_PROFILE_ID = "agent.trace" as const;
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const OUTCOMES = new Set(["ok", "error", "denied", "checkpoint"]);
const STAGE_STATUS = new Set(["ok", "error", "skipped"]);
function isNonEmptyString(v: unknown): v is string { return typeof v === "string" && v.length > 0; }
function isNonNegInt(v: unknown): v is number { return typeof v === "number" && Number.isInteger(v) && v >= 0; }
function isSha256(v: unknown): v is string { return typeof v === "string" && SHA256_HEX_RE.test(v); }

export function validateAgentTrace(body: AgTRBody): ProfileValidationResult {
  const b = body as unknown as Record<string, unknown>;
  const errors: string[] = [];
  if (b.profile !== "agent.trace") errors.push("trace.wrong_profile");
  if (!isSha256(b.request_id_commit)) errors.push("trace.request_id_commit_malformed");
  if (b.capability !== undefined && !isNonEmptyString(b.capability)) errors.push("trace.capability_invalid");
  if (!Array.isArray(b.stages) || b.stages.length === 0) {
    errors.push("trace.stages_empty");
  } else {
    b.stages.forEach((s, i) => {
      const st = s as Record<string, unknown>;
      if (!isNonEmptyString(st.stage)) errors.push(`trace.stages.${i}.stage_invalid`);
      if (!isNonNegInt(st.ms)) errors.push(`trace.stages.${i}.ms_invalid`);
      if (typeof st.status !== "string" || !STAGE_STATUS.has(st.status)) errors.push(`trace.stages.${i}.status_invalid`);
    });
  }
  if (typeof b.outcome !== "string" || !OUTCOMES.has(b.outcome)) errors.push("trace.outcome_invalid");
  if (b.outcome === "error" && !isNonEmptyString(b.error_stage)) errors.push("trace.error_stage_missing");
  if (b.error_stage !== undefined && !isNonEmptyString(b.error_stage)) errors.push("trace.error_stage_invalid");
  if (!isSha256(b.trace_commit)) errors.push("trace.trace_commit_malformed");
  if (!isNonEmptyString(b.started_at)) errors.push("trace.started_at_missing");
  else if (!RFC3339_RE.test(b.started_at) || Number.isNaN(Date.parse(b.started_at))) errors.push("trace.started_at_invalid");
  if (!isNonNegInt(b.total_ms)) errors.push("trace.total_ms_invalid");
  if (b.policy_hash !== undefined && !isSha256(b.policy_hash)) errors.push("trace.policy_hash_malformed");
  if (b.credential_id !== undefined && !isNonEmptyString(b.credential_id)) errors.push("trace.credential_id_invalid");
  if (b.caveats_consumed !== undefined && b.credential_id === undefined) errors.push("trace.caveats_orphan");
  return { errors };
}

export const validateAgentTraceProfile = makeProfileAdapter(
  AGENT_TRACE_PROFILE_ID, (body) => validateAgentTrace(body as AgTRBody),
);
