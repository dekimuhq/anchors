/**
 * SignedSpanExporter — an OpenTelemetry SpanExporter (duck-typed to avoid a hard
 * @opentelemetry/* compile dep) that converts each batch to an AgTR v2 body and mints
 * a signed receipt via a caller-provided mint fn. THIS is "the OTel exporter that signs
 * spans." The mint fn wires to mintTraceV2 (with the issuer's signing key + salt source);
 * the sink persists/forwards the signed envelope.
 */
import { toAgTRTree } from "./convert.ts";
import type { AgTRTreeBody } from "./types.ts";

export interface SignedSpanExporterOpts {
  /** Wire to mintTraceV2 in @dekimuhq/trace (adds signingKey/anchor/salts issuer-side). */
  mint: (body: Omit<AgTRTreeBody, "spans_root">, detail: Record<string, unknown>) => Promise<unknown>;
  sink: (envelope: unknown) => void | Promise<void>;
  request_id_commit: string;
  outcome?: (spans: unknown[]) => AgTRTreeBody["outcome"];
  capability?: string;
}

type ExportResult = { code: number; error?: Error };

export class SignedSpanExporter {
  readonly #opts: SignedSpanExporterOpts;

  constructor(opts: SignedSpanExporterOpts) {
    this.#opts = opts;
  }

  export(spans: unknown[], resultCallback: (result: ExportResult) => void): void {
    void this.#run(spans).then(
      () => resultCallback({ code: 0 }),
      (error: Error) => resultCallback({ code: 1, error }),
    );
  }

  async #run(spans: unknown[]): Promise<void> {
    if (spans.length === 0) return;
    const { trace_id, started_at, total_ms, skeleton, detail } = toAgTRTree(spans as never[]);
    const body: Omit<AgTRTreeBody, "spans_root"> = {
      profile: "agent.trace",
      trace_id,
      request_id_commit: this.#opts.request_id_commit,
      spans: skeleton,
      outcome: this.#opts.outcome ? this.#opts.outcome(spans) : "ok",
      started_at,
      total_ms,
      ...(this.#opts.capability !== undefined ? { capability: this.#opts.capability } : {}),
    };
    const envelope = await this.#opts.mint(body, detail);
    await this.#opts.sink(envelope);
  }

  async shutdown(): Promise<void> {}
  async forceFlush(): Promise<void> {}
}
