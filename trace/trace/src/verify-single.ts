/**
 * AgTR body verifier (spec §6). SHAPE ONLY — not a behavior or authorization check.
 * Records the issuer's asserted execution path; NEVER re-executes or re-derives.
 * Single profile: agent.trace.
 */
import type { AgTRBody, AgTRCaveatsConsumed } from "./types.ts";

export interface VerifyBodyResult { valid: boolean; errors: string[]; body: AgTRBody | null; }

const OUTCOMES = new Set<string>(["ok", "error", "denied", "checkpoint"]);
const STAGE_STATUS = new Set<string>(["ok", "error", "skipped"]);
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function isNonEmptyString(v: unknown): v is string { return typeof v === "string" && v.length > 0; }
function isNonNegInt(v: unknown): v is number { return typeof v === "number" && Number.isInteger(v) && v >= 0; }
function isSha256(v: unknown): v is string { return typeof v === "string" && SHA256_HEX_RE.test(v); }
function isCaveatsConsumed(v: unknown): v is AgTRCaveatsConsumed {
  if (typeof v !== "object" || v === null) return false;
  const c = v as Record<string, unknown>;
  return (
    isNonEmptyString(c.data_scope) &&
    typeof c.spend_step === "number" && Number.isFinite(c.spend_step) && c.spend_step >= 0 &&
    (c.spend_currency === undefined || isNonEmptyString(c.spend_currency)) &&
    isNonEmptyString(c.capability)
  );
}

export function verifyTraceBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];
  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  if (b.profile !== "agent.trace") errors.push("profile.invalid");
  if (!isSha256(b.request_id_commit)) errors.push(b.request_id_commit === undefined ? "request_id_commit.missing" : "request_id_commit.invalid");
  if (b.capability !== undefined && !isNonEmptyString(b.capability)) errors.push("capability.invalid");

  if (!Array.isArray(b.stages) || b.stages.length === 0) {
    errors.push("stages.empty");
  } else {
    b.stages.forEach((s, i) => {
      const st = s as Record<string, unknown>;
      if (!isNonEmptyString(st.stage)) errors.push(`stages[${i}].stage.invalid`);
      if (!isNonNegInt(st.ms)) errors.push(`stages[${i}].ms.invalid`);
      if (typeof st.status !== "string" || !STAGE_STATUS.has(st.status)) errors.push(`stages[${i}].status.invalid`);
    });
  }

  if (typeof b.outcome !== "string" || !OUTCOMES.has(b.outcome)) errors.push("outcome.invalid");
  if (b.outcome === "error" && !isNonEmptyString(b.error_stage)) errors.push("error_stage.missing");
  if (b.error_stage !== undefined && !isNonEmptyString(b.error_stage)) errors.push("error_stage.invalid");

  if (!isSha256(b.trace_commit)) errors.push(b.trace_commit === undefined ? "trace_commit.missing" : "trace_commit.invalid");

  if (!isNonEmptyString(b.started_at)) errors.push("started_at.missing");
  else if (!RFC3339_RE.test(b.started_at) || Number.isNaN(Date.parse(b.started_at))) errors.push("started_at.invalid");

  if (!isNonNegInt(b.total_ms)) errors.push("total_ms.invalid");

  if (b.policy_hash !== undefined && !isSha256(b.policy_hash)) errors.push("policy_hash.invalid");
  if (b.credential_id !== undefined && !isNonEmptyString(b.credential_id)) errors.push("credential_id.invalid");
  if (b.caveats_consumed !== undefined && !isCaveatsConsumed(b.caveats_consumed)) errors.push("caveats_consumed.invalid");
  if (b.caveats_consumed !== undefined && b.credential_id === undefined) errors.push("caveats_consumed.orphan");

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AgTRBody };
}
