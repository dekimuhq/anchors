import { test } from "node:test";
import assert from "node:assert/strict";
import { merkleRoot, auditPath, consistencyPath } from "../src/tree.ts";
import { verifyInclusionProof, verifyConsistencyProof, hashLeaf } from "../src/rfc6962.ts";

function leaves(n: number): Buffer[] {
  return Array.from({ length: n }, (_, i) => hashLeaf(Buffer.from(`leaf-${i}`)));
}

test("audit path verifies against the root for every index, sizes 1..32", () => {
  for (let n = 1; n <= 32; n++) {
    const ls = leaves(n);
    const root = merkleRoot(ls);
    for (let i = 0; i < n; i++) {
      const leaf = ls[i];
      if (!leaf) throw new Error(`leaf ${i} undefined`);
      assert.ok(verifyInclusionProof(leaf, i, n, auditPath(ls, i), root), `n=${n} i=${i}`);
    }
  }
});

test("single-leaf tree: root equals the leaf, empty audit path", () => {
  const ls = leaves(1);
  const l0 = ls[0];
  if (!l0) throw new Error("leaf 0 undefined");
  assert.ok(merkleRoot(ls).equals(l0));
  assert.deepEqual(auditPath(ls, 0), []);
});

test("consistencyPath verifies append-only between every old<new up to 16", () => {
  for (let n = 2; n <= 16; n++) {
    const ls = leaves(n);
    const newRoot = merkleRoot(ls);
    for (let m = 1; m < n; m++) {
      const oldRoot = merkleRoot(ls.slice(0, m));
      const proof = consistencyPath(ls, m, n);
      assert.ok(verifyConsistencyProof(m, n, proof, oldRoot, newRoot), `m=${m} n=${n}`);
    }
  }
});
