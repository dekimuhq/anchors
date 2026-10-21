import { test } from "node:test";
import assert from "node:assert/strict";
import { buildTree, inclusionProof, verifyInclusion } from "../src/merkle.ts";

const LEAVES_4 = [
  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  "sha256:3333333333333333333333333333333333333333333333333333333333333333",
  "sha256:4444444444444444444444444444444444444444444444444444444444444444",
];

test("buildTree returns a stable root for the same leaves", () => {
  const a = buildTree(LEAVES_4);
  const b = buildTree(LEAVES_4);
  assert.equal(a.root, b.root);
  assert.match(a.root, /^sha256:[0-9a-f]{64}$/);
});

test("buildTree root changes if any leaf changes", () => {
  const a = buildTree(LEAVES_4);
  const changed = [...LEAVES_4];
  changed[2] = "sha256:" + "f".repeat(64);
  const b = buildTree(changed);
  assert.notEqual(a.root, b.root);
});

test("single-leaf tree has root === leaf (with leaf prefix)", () => {
  const t = buildTree([LEAVES_4[0]!]);
  // Single-leaf root is still hashed with leaf prefix 0x00 per RFC 6962.
  assert.match(t.root, /^sha256:[0-9a-f]{64}$/);
});

test("inclusion proof verifies correctly for every leaf", () => {
  const t = buildTree(LEAVES_4);
  for (let i = 0; i < LEAVES_4.length; i++) {
    const proof = inclusionProof(t, i);
    const ok = verifyInclusion(LEAVES_4[i]!, proof, i, LEAVES_4.length, t.root);
    assert.equal(ok, true, `proof at index ${i} should verify`);
  }
});

test("inclusion proof fails for wrong leaf", () => {
  const t = buildTree(LEAVES_4);
  const proof = inclusionProof(t, 0);
  const ok = verifyInclusion(LEAVES_4[1]!, proof, 0, LEAVES_4.length, t.root);
  assert.equal(ok, false);
});

test("odd-leaf-count trees are supported", () => {
  const leaves = LEAVES_4.slice(0, 3);
  const t = buildTree(leaves);
  for (let i = 0; i < leaves.length; i++) {
    const proof = inclusionProof(t, i);
    assert.equal(verifyInclusion(leaves[i]!, proof, i, leaves.length, t.root), true);
  }
});

test("single-leaf tree verifies with empty proof", () => {
  const t = buildTree([LEAVES_4[0]!]);
  const ok = verifyInclusion(LEAVES_4[0]!, [], 0, 1, t.root);
  assert.equal(ok, true);
});

test("parseHash rejects odd-length hex (via verifyInclusion failure path)", () => {
  // Malformed hash routed through verifyInclusion → leafHash → parseHash.
  const malformed = "sha256:" + "1".repeat(63);
  assert.throws(
    () => verifyInclusion(malformed, [], 0, 1, "sha256:" + "0".repeat(64)),
    /expected 64 hex chars/,
  );
});

test("parseHash rejects non-hex chars (via verifyInclusion failure path)", () => {
  const malformed = "sha256:zz" + "1".repeat(62);
  assert.throws(
    () => verifyInclusion(malformed, [], 0, 1, "sha256:" + "0".repeat(64)),
    /non-hex chars in hash/,
  );
});
