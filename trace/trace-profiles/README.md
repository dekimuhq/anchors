# @dekimuhq/trace-profiles

Body type definitions and the `agent.trace` profile validator for Anchored Agent-Trace Receipts (AgTR, `ar.trace.v1`). AgTR receipts assert execution provenance — an ordered pipeline-stage skeleton with timing and outcome — joined to the corresponding AActR and AQR via a salted `request_id_commit`. This package provides the `AgTRBody` interface, shared discriminator types, and the advisory `validateAgentTrace` validator that checks structural correctness of an `agent.trace` body before it is signed by the issuer kit.
