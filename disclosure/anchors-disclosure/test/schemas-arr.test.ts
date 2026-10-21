import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveLayout } from "../src/tree.ts";
import { ARR_SINGLE_DISCLOSURE_SCHEMA, ARR_BATCH_DISCLOSURE_SCHEMA } from "../src/schemas/arr.ts";

// An ARR single (ar.erasure.v1) body shape.
const arrSingleBody = {
  profile: "gdpr.art17",
  target_kind: "subject",
  target_commit: "sha256:" + "c".repeat(64),
  salt_epoch: "2026-01",
  policy_hash: "sha256:" + "d".repeat(64),
  policy_uri: "https://example.com/policy.pdf",
  policy_version: "1.0.0",
  trigger: "operator",
  trigger_receipt: null,
  event_at: "2026-05-17T10:00:00Z",
  granted_at: "2026-05-17T10:00:01Z",
  effective_until: null,
  state_snapshot: { retention_status: "erased" },
  field_root: "sha256:" + "f".repeat(64), // present at verify time; not a declared leaf
  qts_attestation_hash: null,
};

// An ARR batch (ar.batch.v1) body shape.
const arrBatchBody = {
  profile: "gdpr.art17",
  batch_event_kind: "ar.erasure.v1",
  target_kind: "subject",
  target_root: "sha256:" + "1".repeat(64),
  target_count: 2,
  salt_epoch: "2026-01",
  policy_hash: "sha256:" + "d".repeat(64),
  policy_uri: "https://example.com/policy.pdf",
  policy_version: "1.0.0",
  trigger: "scheduled",
  trigger_receipt: null,
  event_at: "2026-05-17T10:00:00Z",
  granted_at: "2026-05-17T10:00:01Z",
  effective_until: null,
  state_snapshot_root: "sha256:" + "2".repeat(64),
  field_root: "sha256:" + "f".repeat(64),
  qts_attestation_hash: null,
};

test("ARR single schema declares four always-present scalar leaves", () => {
  assert.deepEqual(ARR_SINGLE_DISCLOSURE_SCHEMA.leaves.map((l) => l.path), [
    "/profile",
    "/target_kind",
    "/trigger",
    "/event_at",
  ]);
  assert.equal(ARR_SINGLE_DISCLOSURE_SCHEMA.leaves.every((l) => !l.array), true);
});

test("ARR single schema resolves cleanly against an erasure body", () => {
  const layout = resolveLayout(arrSingleBody, ARR_SINGLE_DISCLOSURE_SCHEMA);
  assert.deepEqual(layout.map((l) => l.path), ["/profile", "/target_kind", "/trigger", "/event_at"]);
  assert.deepEqual(layout.map((l) => l.value), ["gdpr.art17", "subject", "operator", "2026-05-17T10:00:00Z"]);
});

test("ARR batch schema declares four always-present scalar leaves", () => {
  assert.deepEqual(ARR_BATCH_DISCLOSURE_SCHEMA.leaves.map((l) => l.path), [
    "/profile",
    "/batch_event_kind",
    "/target_kind",
    "/event_at",
  ]);
  assert.equal(ARR_BATCH_DISCLOSURE_SCHEMA.leaves.every((l) => !l.array), true);
});

test("ARR batch schema resolves cleanly against a batch body", () => {
  const layout = resolveLayout(arrBatchBody, ARR_BATCH_DISCLOSURE_SCHEMA);
  assert.deepEqual(layout.map((l) => l.value), ["gdpr.art17", "ar.erasure.v1", "subject", "2026-05-17T10:00:00Z"]);
});
