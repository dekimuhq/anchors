/**
 * OTel span data-model ⇄ AgTR v2 conversion. Reads only the stable ReadableSpan
 * surface (name, spanContext(), parentSpanId, startTime/endTime hrTime tuples, status
 * code, attributes). The receipt stays a signed anchors envelope — this is NOT OTLP wire.
 */
import type { Span } from "./types.ts";

type HrTime = [number, number]; // [unixSeconds, nanos]
const hrToMs = (t: HrTime): number => t[0] * 1000 + t[1] / 1e6;
const OTEL_STATUS: Record<number, Span["status"]> = { 0: "unset", 1: "ok", 2: "error" };

interface ReadableSpanLike {
  name: string;
  spanContext(): { traceId: string; spanId: string };
  parentSpanId?: string;
  startTime: HrTime;
  endTime: HrTime;
  status?: { code?: number };
  attributes?: Record<string, unknown>;
}

export interface ConvertResult {
  trace_id: string;
  started_at: string;
  total_ms: number;
  skeleton: Span[];
  detail: Record<string, unknown>;
}

export function toAgTRTree(spans: ReadableSpanLike[]): ConvertResult {
  if (spans.length === 0) throw new Error("toAgTRTree: no spans");
  const traceStartMs = Math.min(...spans.map((s) => hrToMs(s.startTime)));
  const traceEndMs = Math.max(...spans.map((s) => hrToMs(s.endTime)));
  const trace_id = spans[0].spanContext().traceId;
  const skeleton: Span[] = [];
  const detail: Record<string, unknown> = {};
  for (const s of spans) {
    const ctx = s.spanContext();
    const startMs = hrToMs(s.startTime);
    skeleton.push({
      span_id: ctx.spanId,
      parent_span_id: s.parentSpanId ?? null,
      name: s.name,
      start_offset_ms: Math.max(0, Math.round(startMs - traceStartMs)),
      duration_ms: Math.max(0, Math.round(hrToMs(s.endTime) - startMs)),
      status: OTEL_STATUS[s.status?.code ?? 0] ?? "unset",
    });
    detail[ctx.spanId] = { name: s.name, attributes: s.attributes ?? {} };
  }
  return {
    trace_id,
    started_at: new Date(traceStartMs).toISOString(),
    total_ms: Math.max(0, Math.round(traceEndMs - traceStartMs)),
    skeleton,
    detail,
  };
}
