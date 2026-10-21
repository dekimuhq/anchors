import { test } from "node:test";
import assert from "node:assert/strict";
import { buildTree, inclusionProof, verifyInclusion } from "../src/merkle.ts";

const H = (n: number) => `sha256:${n.toString(16).padStart(64, "0")}`;

test("buildTree + inclusionProof + verifyInclusion round-trip (4 leaves)", () => {
  const leaves = [H(1), H(2), H(3), H(4)];
  const tree = buildTree(leaves);
  for (let i = 0; i < leaves.length; i++) {
    const proof = inclusionProof(tree, i);
    assert.equal(verifyInclusion(leaves[i]!, proof, i, leaves.length, tree.root), true);
  }
});

test("verifyInclusion rejects a wrong leaf", () => {
  const leaves = [H(1), H(2), H(3)];
  const tree = buildTree(leaves);
  const proof = inclusionProof(tree, 0);
  assert.equal(verifyInclusion(H(99), proof, 0, leaves.length, tree.root), false);
});

test("buildTree throws on empty", () => {
  assert.throws(() => buildTree([]));
});
