import { test } from "node:test";
import assert from "node:assert/strict";
import { generateIssuerKey, encodePublicKey, mintBatch } from "../src/issue/index.ts";
import { verifyBatchReceipt, MAX_BATCH_TARGET_COUNT } from "../src/index.ts";
import type { ArrStateSnapshot } from "../src/index.ts";

const KP = generateIssuerKey();
const ISS = "did:web:bank.example";

function snapshot(s: Partial<ArrStateSnapshot> = {}): ArrStateSnapshot {
  return {
    retention_status: "expired",
    current_policy_hash: "sha256:" + "cd".repeat(32),
    hold_active: false,
    hold_reason_commit: null,
    anonymized: false,
    archived: false,
    ...s,
  };
}

test("mintBatch with 4 targets yields verifiable batch", () => {
  const targets = [
    { target_commit: "sha256:" + "01".repeat(32), state_snapshot: snapshot() },
    { target_commit: "sha256:" + "02".repeat(32), state_snapshot: snapshot() },
    { target_commit: "sha256:" + "03".repeat(32), state_snapshot: snapshot() },
    { target_commit: "sha256:" + "04".repeat(32), state_snapshot: snapshot() },
  ];

  const b = mintBatch({
    iss: ISS,
    iss_key: encodePublicKey(KP.publicKey),
    privateKey: KP.privateKey,
    profile: "gdpr.art5e",
    batch_event_kind: "ar.expiry.v1",
    target_kind: "subject",
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "cd".repeat(32),
    policy_uri: "https://bank.example/p",
    policy_version: "1.0.0",
    trigger: "scheduled",
    trigger_receipt: null,
    event_at: "2026-05-16T03:00:00Z",
    granted_at: "2026-05-16T03:01:00Z",
    targets,
  });

  assert.equal(b.kind, "ar.batch.v1");
  assert.equal(b.target_count, 4);

  const out = verifyBatchReceipt(b, {
    anchorInclusionTime: "2026-05-16T03:02:00Z",
    disclosedTargets: targets.map((t) => t.target_commit),
  });
  assert.equal(out.valid, true);
});

test("mintBatch throws above MAX_BATCH_TARGET_COUNT", () => {
  const targets = new Array(MAX_BATCH_TARGET_COUNT + 1).fill(0).map((_, i) => ({
    target_commit: "sha256:" + i.toString(16).padStart(64, "0"),
    state_snapshot: snapshot(),
  }));
  assert.throws(
    () =>
      mintBatch({
        iss: ISS,
        iss_key: encodePublicKey(KP.publicKey),
        privateKey: KP.privateKey,
        profile: "gdpr.art5e",
        batch_event_kind: "ar.expiry.v1",
        target_kind: "subject",
        salt_epoch: "2026Q2",
        policy_hash: "sha256:" + "cd".repeat(32),
        policy_uri: "https://bank.example/p",
        policy_version: "1.0.0",
        trigger: "scheduled",
        trigger_receipt: null,
        event_at: "2026-05-16T03:00:00Z",
        granted_at: "2026-05-16T03:01:00Z",
        targets,
      }),
    /target_count.exceeds_max/,
  );
});

test("mintBatch with empty targets throws", () => {
  assert.throws(
    () =>
      mintBatch({
        iss: ISS,
        iss_key: encodePublicKey(KP.publicKey),
        privateKey: KP.privateKey,
        profile: "gdpr.art5e",
        batch_event_kind: "ar.expiry.v1",
        target_kind: "subject",
        salt_epoch: "2026Q2",
        policy_hash: "sha256:" + "cd".repeat(32),
        policy_uri: "https://bank.example/p",
        policy_version: "1.0.0",
        trigger: "scheduled",
        trigger_receipt: null,
        event_at: "2026-05-16T03:00:00Z",
        granted_at: "2026-05-16T03:01:00Z",
        targets: [],
      }),
    /target_count.zero/,
  );
});
