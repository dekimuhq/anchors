# @dekimuhq/action

**Anchored Action Receipts (AActR)** — verify (default) + issue (`./issue`).

The 15th member of the [Anchors](https://github.com/dekimuhq/anchors-spec) family
(chip 15, wire noun `ar.action.v1`). AActR mints one signed, Merkle-anchored
receipt per **autonomous** action taken by an automation engine on a workspace's
behalf:

> Under owner-enabled rule **R**, the engine executed verb **V** against decision
> **D** for workspace **W** at time **T**, with outcome **O**.

It is a **null-subject, workspace-level event receipt** (not a data-subject
receipt). It reuses the `@dekimuhq/anchors-envelope` v=2 Ed25519 core verbatim —
no new cryptographic primitive.

## Install

```bash
npm install @dekimuhq/action
```

## Verify

```ts
import { verifyReceipt } from "@dekimuhq/action";

const result = await verifyReceipt(envelope, { resolveKey });
// result.signature_valid, result.body_valid, result.profile_valid, ...
```

## Issue

```ts
import { mintActionV2 } from "@dekimuhq/action/issue";
import { commit } from "@dekimuhq/anchors-envelope";

const env = await mintActionV2({
  issuer: "did:web:app.dekimu.com",
  signingKey,
  anchor,
  profile: "hub.automation",
  verb: "invoiceup.remind",
  rule_id: "r1",
  recipe_id: "auto-remind-overdue",
  outcome: "executed",
  executed_at: new Date().toISOString(),
  decision_commit: commit(salt, JSON.stringify(decisionId)),
  params_commit: commit(salt, JSON.stringify(params)),
  request_id_commit: commit(salt, JSON.stringify(`${ruleId}:${decisionId}`)),
  policy_uri: "https://app.dekimu.com/automations",
  policy_hash: RECIPE_CATALOG_HASH,
  policy_version: "plan-2.v1",
});
```

The three `*_commit` fields are salted commits over low-entropy / possibly-PII
target values (`commit(salt, …)`), keeping the publicly-anchored receipt
GDPR-clean while still binding the exact action. Salts live in an app-side
reveal map, never in the signed envelope.

## Design

https://github.com/dekimuhq/anchors-spec/tree/main/action

## License

Apache-2.0
