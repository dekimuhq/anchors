import { test } from "node:test";
import assert from "node:assert/strict";
import type {
  ArrKind,
  ArrBatchEventKind,
  ArrProfile,
  ArrTrigger,
  ArrTargetKind,
  ArrRetentionStatus,
  ARRReceipt,
  ARRBatchReceipt,
  ArrAnchor,
} from "../src/types.ts";

test("ArrKind covers 7 single kinds + ar.batch.v1", () => {
  const all: ArrKind[] = [
    "ar.erasure.v1",
    "ar.expiry.v1",
    "arr.hold_extension.v1",
    "arr.hold_release.v1",
    "ar.anonymization.v1",
    "arr.pseudonymization.v1",
    "ar.archive.v1",
    "ar.batch.v1",
  ];
  assert.equal(all.length, 8);
});

test("ArrBatchEventKind excludes ar.batch.v1", () => {
  const all: ArrBatchEventKind[] = [
    "ar.erasure.v1",
    "ar.expiry.v1",
    "arr.hold_extension.v1",
    "arr.hold_release.v1",
    "ar.anonymization.v1",
    "arr.pseudonymization.v1",
    "ar.archive.v1",
  ];
  assert.equal(all.length, 7);
});

test("ArrProfile covers 7 v1.0 profiles", () => {
  const all: ArrProfile[] = [
    "gdpr.art17",
    "gdpr.art5e",
    "hipaa.retention",
    "kyc.retention",
    "sox.retention",
    "mifid2.retention",
    "aiact.art10",
  ];
  assert.equal(all.length, 7);
});

test("ArrTrigger has 5 values", () => {
  const all: ArrTrigger[] = [
    "subject_request",
    "scheduled",
    "legal_order",
    "regulator_order",
    "operator",
  ];
  assert.equal(all.length, 5);
});

test("ArrTargetKind has subject + artifact", () => {
  const all: ArrTargetKind[] = ["subject", "artifact"];
  assert.equal(all.length, 2);
});

test("ArrRetentionStatus has 6 values per §4.5", () => {
  const all: ArrRetentionStatus[] = [
    "active",
    "erased",
    "expired",
    "archived",
    "anonymized",
    "pseudonymized",
  ];
  assert.equal(all.length, 6);
});

test("ARRReceipt accepts a minimal single-target erasure receipt shape", () => {
  const r: ARRReceipt = {
    kind: "ar.erasure.v1",
    profile: "gdpr.art17",
    iss: "did:web:bank.example",
    iss_key: "ed25519:AAAA",
    target_kind: "subject",
    target_commit: "sha256:00",
    salt_epoch: "2026Q2",
    policy_hash: "sha256:01",
    policy_uri: "https://bank.example/p/v3",
    policy_version: "3.1.0",
    trigger: "subject_request",
    trigger_receipt: "sha256:02",
    event_at: "2026-05-16T09:12:00Z",
    granted_at: "2026-05-16T09:14:00Z",
    effective_until: null,
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: "sha256:01",
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
    prev: null,
    field_root: "sha256:03",
    anchor: null,
    sig: null,
  };
  assert.equal(r.kind, "ar.erasure.v1");
});

test("ARRBatchReceipt accepts a minimal batch shape", () => {
  const r: ARRBatchReceipt = {
    kind: "ar.batch.v1",
    profile: "gdpr.art5e",
    iss: "did:web:bank.example",
    iss_key: "ed25519:AAAA",
    batch_event_kind: "ar.expiry.v1",
    target_kind: "subject",
    target_root: "sha256:10",
    target_count: 12483,
    salt_epoch: "2026Q2",
    policy_hash: "sha256:11",
    policy_uri: "https://bank.example/p/v3",
    policy_version: "3.1.0",
    trigger: "scheduled",
    trigger_receipt: null,
    event_at: "2026-05-16T03:00:00Z",
    granted_at: "2026-05-16T03:05:00Z",
    effective_until: null,
    state_snapshot_root: "sha256:12",
    field_root: "sha256:13",
    anchor: null,
    sig: null,
  };
  assert.equal(r.target_count, 12483);
});

test("ArrAnchor matches APR/ACR shape", () => {
  const a: ArrAnchor = {
    log: "https://verify.dekimu.com/arr/v1",
    leaf_index: 102451,
    inclusion_proof: ["sha256:aa", "sha256:bb"],
  };
  assert.equal(a.leaf_index, 102451);
});
