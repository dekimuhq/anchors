import type { MintTraceV2Input } from "../../src/issue/mint-v2.ts";
import { makeSigningKey, makeAnchor } from "./fixtures.ts";

/** Full, valid mintTraceV2 input — agent.trace span-tree profile. */
export function goodTreeInput(): MintTraceV2Input {
  const a = "1".repeat(16), b = "2".repeat(16);
  return {
    issuer: "iss.test",
    signingKey: makeSigningKey(),
    anchor: makeAnchor(),
    trace_id: "a".repeat(32),
    request_id_commit: "sha256:" + "a".repeat(64),
    spans: [
      { span_id: a, parent_span_id: null, name: "stage.execute", start_offset_ms: 0, duration_ms: 41, status: "ok" },
      { span_id: b, parent_span_id: a, name: "llm.call", start_offset_ms: 3, duration_ms: 30, status: "ok" },
    ],
    detail: { [a]: { stage: "execute" }, [b]: { model: "claude", tokens: 812 } },
    salts: { saltFor: (id: string) => "salt-" + id },
    outcome: "ok",
    started_at: "2026-07-01T10:00:00Z",
    total_ms: 43,
  };
}
