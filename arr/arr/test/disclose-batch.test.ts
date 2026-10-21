import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  canonicalize,
  buildTree,
  inclusionProof,
  verifyBatchDisclosure,
} from "../src/index.ts";
import type { ArrStateSnapshot } from "../src/index.ts";

function snapshotHash(snapshot: ArrStateSnapshot): string {
  const bytes = new TextEncoder().encode(canonicalize(snapshot));
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

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

test("valid disclosure of single snapshot under root succeeds", () => {
  const snaps = [snapshot({ retention_status: "active" }), snapshot()];
  const leaves = snaps.map(snapshotHash);
  const tree = buildTree(leaves);
  const proof = inclusionProof(tree, 1);
  const out = verifyBatchDisclosure({
    snapshot: snaps[1]!,
    leafIndex: 1,
    proof,
    root: tree.root,
    totalLeaves: 2,
  });
  assert.equal(out.valid, true);
});

test("tampered snapshot -> invalid", () => {
  const snaps = [snapshot({ retention_status: "active" }), snapshot()];
  const leaves = snaps.map(snapshotHash);
  const tree = buildTree(leaves);
  const proof = inclusionProof(tree, 1);
  const tampered = snapshot({ retention_status: "erased" });
  const out = verifyBatchDisclosure({
    snapshot: tampered,
    leafIndex: 1,
    proof,
    root: tree.root,
    totalLeaves: 2,
  });
  assert.equal(out.valid, false);
});

test("leafIndex out of bounds -> invalid", () => {
  const snaps = [snapshot()];
  const leaves = snaps.map(snapshotHash);
  const tree = buildTree(leaves);
  const out = verifyBatchDisclosure({
    snapshot: snaps[0]!,
    leafIndex: 5,
    proof: [],
    root: tree.root,
    totalLeaves: 1,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("leaf_index.out_of_bounds"));
});
