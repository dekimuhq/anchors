/** Minimal ReadableSpan-shaped fixtures — only the fields convert.ts reads. */
export function otelSpan(over: Record<string, unknown> = {}) {
  return {
    name: "stage.execute",
    spanContext: () => ({ traceId: "a".repeat(32), spanId: "1".repeat(16) }),
    parentSpanId: undefined as string | undefined,
    startTime: [1_780_000_000, 0] as [number, number], // [seconds, nanos]
    endTime: [1_780_000_000, 41_000_000] as [number, number],
    status: { code: 1 }, // OTel StatusCode.OK = 1; ERROR = 2; UNSET = 0
    attributes: { "gen_ai.request.model": "claude" },
    ...over,
  };
}
