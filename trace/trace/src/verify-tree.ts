/**
 * AgTR v2 span-tree body verifier (spec §6). SHAPE + STRUCTURE only — not a behavior,
 * timing, or authorization check. Records the issuer's asserted span tree; NEVER
 * re-executes, re-times, or recomputes spans_root (the verifier holds only the skeleton).
 */
import type { AgTRTreeBody, AgTRCaveatsConsumed, Span } from "./types.ts";

export interface VerifyBodyResult { valid: boolean; errors: string[]; body: AgTRTreeBody | null; }

const OUTCOMES = new Set<string>(["ok", "error", "denied", "checkpoint"]);
const SPAN_STATUS = new Set<string>(["unset", "ok", "error"]);
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const TRACE_ID_RE = /^[0-9a-f]{32}$/;
const SPAN_ID_RE = /^[0-9a-f]{16}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isInt0 = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0;
const isSha256 = (v: unknown): v is string => typeof v === "string" && SHA256_RE.test(v);

function isCaveats(v: unknown): v is AgTRCaveatsConsumed {
  if (typeof v !== "object" || v === null) return false;
  const c = v as Record<string, unknown>;
  return isStr(c.data_scope) &&
    typeof c.spend_step === "number" && Number.isFinite(c.spend_step) && c.spend_step >= 0 &&
    (c.spend_currency === undefined || isStr(c.spend_currency)) && isStr(c.capability);
}

/** True if the parent graph over resolvable edges contains a cycle. */
function hasCycle(spans: Span[]): boolean {
  const parent = new Map<string, string | null>();
  for (const s of spans) parent.set(s.span_id, s.parent_span_id);
  for (const start of parent.keys()) {
    let cur: string | null | undefined = start;
    let steps = 0;
    const max = parent.size + 1;
    while (cur != null) {
      if (++steps > max) return true;       // walked past every node → cycle
      cur = parent.get(cur);
      if (cur === start) return true;
    }
  }
  return false;
}

export function verifyTraceTreeBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];
  if (typeof body !== "object" || body === null) return { valid: false, errors: ["body.not_object"], body: null };
  const b = body as Record<string, unknown>;

  if (b.profile !== "agent.trace") errors.push("profile.invalid");
  if (!isStr(b.trace_id) || !TRACE_ID_RE.test(b.trace_id as string)) errors.push(b.trace_id === undefined ? "trace_id.missing" : "trace_id.invalid");
  if (!isSha256(b.request_id_commit)) errors.push(b.request_id_commit === undefined ? "request_id_commit.missing" : "request_id_commit.invalid");
  if (b.capability !== undefined && !isStr(b.capability)) errors.push("capability.invalid");

  const ids = new Set<string>();
  if (!Array.isArray(b.spans) || b.spans.length === 0) {
    errors.push("spans.empty");
  } else {
    for (const s of b.spans) {
      const sp = s as Record<string, unknown>;
      if (isStr(sp.span_id) && SPAN_ID_RE.test(sp.span_id as string)) {
        if (ids.has(sp.span_id as string)) errors.push("spans.span_id.duplicate");
        ids.add(sp.span_id as string);
      }
    }
    let roots = 0;
    b.spans.forEach((s, i) => {
      const sp = s as Record<string, unknown>;
      if (!isStr(sp.span_id) || !SPAN_ID_RE.test(sp.span_id as string)) errors.push(`spans[${i}].span_id.invalid`);
      if (sp.parent_span_id === null) roots++;
      else if (!isStr(sp.parent_span_id) || !ids.has(sp.parent_span_id as string)) errors.push(`spans[${i}].parent.unresolved`);
      if (!isStr(sp.name)) errors.push(`spans[${i}].name.invalid`);
      if (!isInt0(sp.start_offset_ms)) errors.push(`spans[${i}].start_offset_ms.invalid`);
      if (!isInt0(sp.duration_ms)) errors.push(`spans[${i}].duration_ms.invalid`);
      if (typeof sp.status !== "string" || !SPAN_STATUS.has(sp.status)) errors.push(`spans[${i}].status.invalid`);
    });
    if (roots === 0) errors.push("spans.no_root");
    const clean = (b.spans as unknown[]).every((s) => {
      const sp = s as Record<string, unknown>;
      return isStr(sp.span_id) && SPAN_ID_RE.test(sp.span_id as string) &&
        (sp.parent_span_id === null || (isStr(sp.parent_span_id) && ids.has(sp.parent_span_id as string)));
    });
    if (clean && hasCycle(b.spans as Span[])) errors.push("spans.cycle");
  }

  if (!isSha256(b.spans_root)) errors.push(b.spans_root === undefined ? "spans_root.missing" : "spans_root.invalid");
  if (typeof b.outcome !== "string" || !OUTCOMES.has(b.outcome)) errors.push("outcome.invalid");
  if (b.outcome === "error" && !isStr(b.error_span_id)) errors.push("error_span_id.missing");
  if (b.error_span_id !== undefined && (!isStr(b.error_span_id) || !ids.has(b.error_span_id as string))) errors.push("error_span_id.unresolved");

  if (!isStr(b.started_at)) errors.push("started_at.missing");
  else if (!RFC3339_RE.test(b.started_at as string) || Number.isNaN(Date.parse(b.started_at as string))) errors.push("started_at.invalid");
  if (!isInt0(b.total_ms)) errors.push("total_ms.invalid");

  if (b.policy_hash !== undefined && !isSha256(b.policy_hash)) errors.push("policy_hash.invalid");
  if (b.credential_id !== undefined && !isStr(b.credential_id)) errors.push("credential_id.invalid");
  if (b.caveats_consumed !== undefined && !isCaveats(b.caveats_consumed)) errors.push("caveats_consumed.invalid");
  if (b.caveats_consumed !== undefined && b.credential_id === undefined) errors.push("caveats_consumed.orphan");

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AgTRTreeBody };
}
