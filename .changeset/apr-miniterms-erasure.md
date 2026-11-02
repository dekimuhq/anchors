---
"@dekimuhq/apr": patch
---

Extend `APRArtifactType` with `miniterms.erasure`: the APR parent miniterms
mints under each `ar.erasure.v1` receipt (its `artifact.hash` is the erased
`forget.destruction.v1` receipt id). Additive and wire-invariant: `claim_type`
stays `ar.provenance.v1`, the verifier does not read the union at runtime, and
every existing receipt verifies byte-equal. `ar.provenance.v1.anchor.json` and
its generated snapshot carry the same enum.
