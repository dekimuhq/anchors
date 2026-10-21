import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import {
  canonicalize,
  base64UrlEncode,
  buildTree,
  verifyBatchReceipt,
  MAX_BATCH_TARGET_COUNT,
} from "../src/index.ts";
import type { ARRBatchReceipt } from "../src/index.ts";

function makeBatch(overrides: Partial<ARRBatchReceipt> = {}): ARRBatchReceipt {
  return {
    kind: "ar.batch.v1",
    profile: "gdpr.art5e",
    iss: "did:web:bank.example",
    iss_key: "ed25519:placeholder",
    batch_event_kind: "ar.expiry.v1",
    target_kind: "subject",
    target_root: "sha256:" + "aa".repeat(32),
    target_count: 4,
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "bb".repeat(32),
    policy_uri: "https://bank.example/p",
    policy_version: "1.0.0",
    trigger: "scheduled",
    trigger_receipt: null,
    event_at: "2026-05-16T03:00:00Z",
    granted_at: "2026-05-16T03:01:00Z",
    effective_until: null,
    state_snapshot_root: "sha256:" + "cc".repeat(32),
    field_root: "sha256:" + "dd".repeat(32),
    anchor: null,
    sig: null,
    ...overrides,
  };
}

function signBatch(b: ARRBatchReceipt) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = spki.subarray(spki.length - 32);
  const pubB64 = base64UrlEncode(rawPub);
  const b2: ARRBatchReceipt = { ...b, iss_key: `ed25519:${pubB64}`, sig: null, anchor: null };
  const msg = new TextEncoder().encode(canonicalize(b2));
  const sigBytes = nodeSign(null, msg, privateKey);
  return { receipt: { ...b2, sig: `ed25519:${base64UrlEncode(sigBytes)}` } as ARRBatchReceipt };
}

test("valid batch receipt -> valid", () => {
  const { receipt } = signBatch(makeBatch());
  const out = verifyBatchReceipt(receipt, { anchorInclusionTime: "2026-05-16T03:02:00Z" });
  assert.equal(out.valid, true);
});

test("target_count exceeds MAX -> invalid", () => {
  const { receipt } = signBatch(makeBatch({ target_count: MAX_BATCH_TARGET_COUNT + 1 }));
  const out = verifyBatchReceipt(receipt, { anchorInclusionTime: "2026-05-16T03:02:00Z" });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("target_count.exceeds_max"));
});

test("target_count must be > 0", () => {
  const { receipt } = signBatch(makeBatch({ target_count: 0 }));
  const out = verifyBatchReceipt(receipt, { anchorInclusionTime: "2026-05-16T03:02:00Z" });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("target_count.zero"));
});

test("disclosed targets: target_root matches buildTree(leaves).root", () => {
  const leaves = [
    "sha256:" + "01".repeat(32),
    "sha256:" + "02".repeat(32),
    "sha256:" + "03".repeat(32),
    "sha256:" + "04".repeat(32),
  ];
  const root = buildTree(leaves).root;
  const { receipt } = signBatch(makeBatch({ target_root: root, target_count: 4 }));
  const out = verifyBatchReceipt(receipt, {
    anchorInclusionTime: "2026-05-16T03:02:00Z",
    disclosedTargets: leaves,
  });
  assert.equal(out.valid, true);
});

test("disclosed targets count mismatch -> invalid", () => {
  const leaves = ["sha256:" + "01".repeat(32), "sha256:" + "02".repeat(32)];
  const root = buildTree(leaves).root;
  const { receipt } = signBatch(makeBatch({ target_root: root, target_count: 4 }));
  const out = verifyBatchReceipt(receipt, {
    anchorInclusionTime: "2026-05-16T03:02:00Z",
    disclosedTargets: leaves,
  });
  assert.ok(out.errors.includes("disclosed_targets.count_mismatch"));
});

test("disclosed targets root mismatch -> invalid", () => {
  const realLeaves = ["sha256:" + "01".repeat(32), "sha256:" + "02".repeat(32)];
  const fakeLeaves = ["sha256:" + "ee".repeat(32), "sha256:" + "ff".repeat(32)];
  const root = buildTree(realLeaves).root;
  const { receipt } = signBatch(makeBatch({ target_root: root, target_count: 2 }));
  const out = verifyBatchReceipt(receipt, {
    anchorInclusionTime: "2026-05-16T03:02:00Z",
    disclosedTargets: fakeLeaves,
  });
  assert.ok(out.errors.includes("disclosed_targets.root_mismatch"));
});

test("invalid batch_event_kind -> invalid", () => {
  const { receipt } = signBatch(makeBatch({
    batch_event_kind: "ar.batch.v1" as never,
  }));
  const out = verifyBatchReceipt(receipt, { anchorInclusionTime: "2026-05-16T03:02:00Z" });
  assert.ok(out.errors.includes("batch_event_kind.invalid"));
});
