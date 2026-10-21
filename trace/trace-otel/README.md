# @dekimuhq/trace-otel

Convert OpenTelemetry spans to signed `ar.trace.v2` (Anchored Agent-Trace Receipts) receipts. Provides a `ReadableSpan` → AgTR converter and a `SignedSpanExporter` (a `SpanExporter` implementation) that emits signed AgTR v2 span-tree receipts. `@opentelemetry/*` is an **optional peer dependency** — the exporter is duck-typed and only needed by consumers who actually wire up the SpanExporter, so the core anchors verifier (`@dekimuhq/trace`) stays OTel-free.
