# `@dekimuhq/trace`

Verifier + issuer-kit for **Anchored Agent-Trace Receipts (AgTR) v1** (`ar.trace.v1`). Chip 18 in the Anchors family. AgTR receipts record the issuer's asserted execution path for an agent operation — stage timings, outcome, and a cryptographic commit to the full trace — providing tamper-evident provenance of _what an agent did_, not a guarantee of correct behavior. The verifier checks shape and Ed25519 signature only; it never re-executes or re-derives the agent logic. The `./issue` subpath exports `mintTraceV1` and key-generation helpers for issuing new receipts.
