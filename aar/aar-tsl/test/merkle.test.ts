import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { buildTree, inclusionProof, verifyInclusion } from "../src/merkle.ts";

describe("merkle", () => {
  const leaves = [
    "sha256:" + "a".repeat(64),
    "sha256:" + "b".repeat(64),
    "sha256:" + "c".repeat(64),
  ];

  describe("buildTree", () => {
    it("produces a root for 3 leaves", () => {
      const tree = buildTree(leaves);
      assert.ok(tree.root.startsWith("sha256:"));
      assert.equal(tree.root.length, 7 + 64);
      assert.equal(tree.leafCount, 3);
    });

    it("is deterministic", () => {
      const a = buildTree(leaves);
      const b = buildTree(leaves);
      assert.equal(a.root, b.root);
    });

    it("different leaves produce different roots", () => {
      const other = [leaves[0]!, leaves[1]!, "sha256:" + "d".repeat(64)];
      assert.notEqual(buildTree(leaves).root, buildTree(other).root);
    });

    it("handles single leaf", () => {
      const tree = buildTree([leaves[0]!]);
      assert.equal(tree.leafCount, 1);
      assert.ok(tree.root.startsWith("sha256:"));
    });

    it("throws on empty leaves", () => {
      assert.throws(() => buildTree([]), /empty/);
    });
  });

  describe("inclusionProof", () => {
    it("returns sibling hashes for each leaf", () => {
      const tree = buildTree(leaves);
      for (let i = 0; i < leaves.length; i++) {
        const proof = inclusionProof(tree, i);
        assert.ok(Array.isArray(proof));
        assert.ok(proof.length > 0);
        for (const h of proof) {
          assert.ok(h.startsWith("sha256:"));
        }
      }
    });

    it("throws on out-of-range index", () => {
      const tree = buildTree(leaves);
      assert.throws(() => inclusionProof(tree, -1), /out of range/);
      assert.throws(() => inclusionProof(tree, 3), /out of range/);
    });
  });

  describe("verifyInclusion", () => {
    it("round-trips: proof generated from tree verifies against root", () => {
      const tree = buildTree(leaves);
      for (let i = 0; i < leaves.length; i++) {
        const proof = inclusionProof(tree, i);
        const ok = verifyInclusion(leaves[i]!, proof, i, tree.leafCount, tree.root);
        assert.equal(ok, true, `leaf ${i} should verify`);
      }
    });

    it("rejects wrong leaf", () => {
      const tree = buildTree(leaves);
      const proof = inclusionProof(tree, 0);
      const ok = verifyInclusion(leaves[1]!, proof, 0, tree.leafCount, tree.root);
      assert.equal(ok, false);
    });

    it("rejects wrong root", () => {
      const tree = buildTree(leaves);
      const proof = inclusionProof(tree, 0);
      const fakeRoot = "sha256:" + "f".repeat(64);
      const ok = verifyInclusion(leaves[0]!, proof, 0, tree.leafCount, fakeRoot);
      assert.equal(ok, false);
    });

    it("rejects wrong index", () => {
      const tree = buildTree(leaves);
      const proof = inclusionProof(tree, 0);
      const ok = verifyInclusion(leaves[0]!, proof, 1, tree.leafCount, tree.root);
      assert.equal(ok, false);
    });

    it("works with power-of-2 leaf count", () => {
      const four = [...leaves, "sha256:" + "d".repeat(64)];
      const tree = buildTree(four);
      for (let i = 0; i < four.length; i++) {
        const proof = inclusionProof(tree, i);
        assert.equal(verifyInclusion(four[i]!, proof, i, tree.leafCount, tree.root), true);
      }
    });

    it("works with large tree (16 leaves)", () => {
      const big = Array.from({ length: 16 }, (_, i) =>
        "sha256:" + i.toString(16).padStart(64, "0"),
      );
      const tree = buildTree(big);
      for (let i = 0; i < big.length; i++) {
        const proof = inclusionProof(tree, i);
        assert.equal(verifyInclusion(big[i]!, proof, i, tree.leafCount, tree.root), true);
      }
    });

    it("rejects out-of-range leafIndex", () => {
      const tree = buildTree(leaves);
      assert.equal(verifyInclusion(leaves[0]!, [], -1, tree.leafCount, tree.root), false);
      assert.equal(verifyInclusion(leaves[0]!, [], 99, tree.leafCount, tree.root), false);
    });

    it("works with 2 leaves (minimal pair)", () => {
      const pair = [leaves[0]!, leaves[1]!];
      const tree = buildTree(pair);
      for (let i = 0; i < pair.length; i++) {
        const proof = inclusionProof(tree, i);
        assert.equal(verifyInclusion(pair[i]!, proof, i, tree.leafCount, tree.root), true);
      }
    });

    it("works with 5 leaves (odd count)", () => {
      const five = Array.from({ length: 5 }, (_, i) =>
        "sha256:" + i.toString(16).padStart(64, "0"),
      );
      const tree = buildTree(five);
      for (let i = 0; i < five.length; i++) {
        const proof = inclusionProof(tree, i);
        assert.equal(verifyInclusion(five[i]!, proof, i, tree.leafCount, tree.root), true);
      }
    });
  });
});
