import { test } from "node:test";
import assert from "node:assert/strict";
import { sha256, hashLeaf, hashNode, verifyInclusionProof, verifyConsistencyProof } from "../src/rfc6962.ts";

test("hashLeaf uses 0x00 prefix, hashNode uses 0x01 (RFC 6962 domain separation)", () => {
  const data = Buffer.from("x");
  assert.ok(hashLeaf(data).equals(sha256(Buffer.concat([Buffer.of(0x00), data]))));
  const l = hashLeaf(Buffer.from("l")), r = hashLeaf(Buffer.from("r"));
  assert.ok(hashNode(l, r).equals(sha256(Buffer.concat([Buffer.of(0x01), l, r]))));
});

test("verifyInclusionProof: a leaf at index i in a tree of n verifies against a recomputed root", () => {
  // proof material is produced by tree.ts (Task 4); here use a 1-leaf tree (empty path)
  const leaf = hashLeaf(Buffer.from("only"));
  assert.ok(verifyInclusionProof(leaf, 0, 1, [], leaf));
});
