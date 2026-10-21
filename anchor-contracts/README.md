# @dekimuhq/anchor-contracts

Deterministic Anchor Contracts runtime for the Anchored Receipts family.

A **contract** is a declarative rule: a set of preconditions over verified anchors,
an optional predicate over the matched set, and a `from → to` state edge. Stack
contracts into a **trust state machine** whose audit trail is the ordered list of
fired transitions.

> **Trust boundary.** This library does NOT verify anchor signatures or Merkle
> proofs. Run the relevant family verifier first and pass its verdict in. The
> trust gate is **deny-by-default**: a contract REFUSES to fire on any anchor whose
> `signature_valid !== true`, or whose `status_state` is present but outside the
> good-standing allowlist `ACCEPTABLE_STATUS_STATES` (so every `revoked*`,
> `suspended*`, and could-not-confirm state — `unreachable`, `invalid_pointer`,
> `list_*` — refuses, not only the exact string `"revoked"`). A `status_state` of
> `undefined` means the caller opted out of revocation checking and is allowed.

Local-only trust model: every party evaluates independently and — because
evaluation is pure — reaches the same verdict from the same inputs. No
coordinator, no chain, no consensus.
