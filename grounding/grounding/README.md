# @dekimuhq/grounding

AGrR (Anchored Grounding Receipts) — verifier + issuer-kit for `ar.grounding.v1`. Records citation-binding and lexical grounding-support provenance for RAG answers. Binding is deterministic and authoritative; score is advisory-by-method. Provenance of grounding, not a truth guarantee.

## Consuming a receipt for a TRUST decision

`verifyReceipt(...)` returns a `FamilyVerifyResult`. **Gate on `result.trust_outcome === "valid_trusted"`, never on `signature_valid` alone** — `signature_valid` means only that the signature and body are well-formed (crypto-intact), NOT that the issuer is trusted. A self-minted, untrusted-key receipt can be `signature_valid: true`.

What the stateless verify path proves vs. not:
- **Authoritative always:** signature + body well-formedness + internal coherence (referential integrity, `coverage`/`grounded_count` arithmetic, support↔score mapping).
- **Authoritative only if you hold the sources:** citation binding — re-check `span_commit === sha256(source[start:end])` and `source_commit === sha256(source)` yourself. The verifier cannot do this without the sources and never silently asserts it.
- **Advisory:** the support `score` is a `lexical_overlap` measurement, not a guarantee the answer is true, complete, or fully grounded.
