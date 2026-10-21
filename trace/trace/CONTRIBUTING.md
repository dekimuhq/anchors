# Contributing to `@dekimuhq/trace`

Thanks for considering a contribution. `@dekimuhq/trace` is the reference verifier + issuer kit for AgTR v1 (Anchored Agent-Trace Receipts). The bar is correctness over features: every change must keep the published conformance vectors passing byte-for-byte.

AgTR records execution **provenance**, not verified behavior. The verifier must NEVER re-derive or re-execute the agent logic — it records the issuer's asserted execution path and checks shape + signature only. Changes that add such re-execution or cross-checks will not be merged.

## What kind of changes land

- **Bug fixes** to verification logic, profile dispatch, or body-shape validation — yes, with a regression test.
- **Performance improvements** that preserve byte-for-byte output on the conformance vectors — yes.
