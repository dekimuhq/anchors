# @dekimuhq/grounding-check

Zero-dependency, deterministic engine that binds the cited claims of a RAG answer to hash-committed source spans and attaches a method-attributed support score — **provenance, not truth**: the binding (span → `sha256` commit) is authoritative, the `lexical_overlap` support score is advisory-by-method, not a guarantee that a claim is true. `node:crypto` only; extraction-ready (drop-in, no `@dekimuhq/*` deps).
