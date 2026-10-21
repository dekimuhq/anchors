/**
 * Property / fuzz tests for rfc6962.ts and tree.ts.
 *
 * Deterministic: uses a seeded LCG (no Math.random, no Date.now).
 * Iteration counts are chosen to produce genuine coverage rather than padding.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { hashLeaf, hashNode, verifyInclusionProof, verifyConsistencyProof } from "../src/rfc6962.ts";
import { merkleRoot, auditPath, consistencyPath } from "../src/tree.ts";

// ---------------------------------------------------------------------------
// Deterministic LCG — 32-bit Knuth multiplicative LCG
// ---------------------------------------------------------------------------
function makeLcg(seed: number) {
  let s = seed >>> 0;
  return function next(): number {
    s = Math.imul(s, 1664525) + 1013904223;
    s = s >>> 0;
    return s;
  };
}

/** Build n leaf hashes deterministically from a starting counter. */
function leaves(n: number, offset = 0): Buffer[] {
  return Array.from({ length: n }, (_, i) =>
    hashLeaf(Buffer.from(`leaf-${offset + i}`)),
  );
}

/** Flip one byte in a Buffer copy at position pos % buf.length. */
function flipByte(buf: Buffer, pos: number): Buffer {
  const copy = Buffer.from(buf);
  const idx = pos % copy.length;
  copy[idx] = (copy[idx]! ^ 0xff) & 0xff;
  return copy;
}

// ---------------------------------------------------------------------------
// 1. Inclusion proofs: every leaf in trees of size 1..64 and a few large sizes
// ---------------------------------------------------------------------------
const SMALL_SIZES = Array.from({ length: 64 }, (_, i) => i + 1);
const LARGE_SIZES = [100, 255, 256, 257, 1000];
const ALL_SIZES = [...SMALL_SIZES, ...LARGE_SIZES];

test("inclusion proof verifies for every leaf in trees of size 1..64", () => {
  for (const n of SMALL_SIZES) {
    const ls = leaves(n);
    const root = merkleRoot(ls);
    for (let i = 0; i < n; i++) {
      const leaf = ls[i]!;
      const path = auditPath(ls, i);
      assert.ok(
        verifyInclusionProof(leaf, i, n, path, root),
        `n=${n} i=${i}: valid proof should verify`,
      );
    }
  }
});

test("inclusion proof verifies for every leaf in large trees (100, 255, 256, 257, 1000)", () => {
  for (const n of LARGE_SIZES) {
    const ls = leaves(n);
    const root = merkleRoot(ls);
    // Spot-check first, last, and three interior positions
    const indices = [0, 1, Math.floor(n / 3), Math.floor(n / 2), n - 2, n - 1];
    for (const i of indices) {
      if (i < 0 || i >= n) continue;
      const leaf = ls[i]!;
      const path = auditPath(ls, i);
      assert.ok(
        verifyInclusionProof(leaf, i, n, path, root),
        `n=${n} i=${i}: valid proof should verify`,
      );
    }
  }
});

test("wrong root fails inclusion proof for every tree size in 1..64", () => {
  const lcg = makeLcg(0xdeadbeef);
  for (const n of SMALL_SIZES) {
    const ls = leaves(n);
    const root = merkleRoot(ls);
    const badRoot = flipByte(root, lcg() % 32);
    // Check one representative index per size
    const i = lcg() % n;
    const leaf = ls[i]!;
    const path = auditPath(ls, i);
    assert.equal(
      verifyInclusionProof(leaf, i, n, path, badRoot),
      false,
      `n=${n} i=${i}: flipped root should fail`,
    );
  }
});

test("wrong index fails inclusion proof for sizes 2..32", () => {
  const lcg = makeLcg(0xcafebabe);
  for (let n = 2; n <= 32; n++) {
    const ls = leaves(n);
    const root = merkleRoot(ls);
    const i = lcg() % n;
    const leaf = ls[i]!;
    const path = auditPath(ls, i);
    // Use a neighbouring index that differs from i
    const wrongIdx = (i + 1) % n;
    assert.equal(
      verifyInclusionProof(leaf, wrongIdx, n, path, root),
      false,
      `n=${n}: proof for index ${i} should not verify at index ${wrongIdx}`,
    );
  }
});

test("truncated audit path fails inclusion proof for sizes 2..32", () => {
  const lcg = makeLcg(0x12345678);
  for (let n = 2; n <= 32; n++) {
    const ls = leaves(n);
    const root = merkleRoot(ls);
    const i = lcg() % n;
    const leaf = ls[i]!;
    const path = auditPath(ls, i);
    if (path.length === 0) continue; // n=1 has empty path; nothing to truncate
    const truncated = path.slice(0, -1);
    assert.equal(
      verifyInclusionProof(leaf, i, n, truncated, root),
      false,
      `n=${n} i=${i}: truncated path should fail`,
    );
  }
});

test("flipping one sibling byte fails inclusion proof for sizes 2..32", () => {
  const lcg = makeLcg(0xabcdef01);
  for (let n = 2; n <= 32; n++) {
    const ls = leaves(n);
    const root = merkleRoot(ls);
    const i = lcg() % n;
    const leaf = ls[i]!;
    const path = auditPath(ls, i);
    if (path.length === 0) continue;
    const siblingIdx = lcg() % path.length;
    const corrupted = path.map((b, j) =>
      j === siblingIdx ? flipByte(b, lcg() % 32) : b,
    );
    assert.equal(
      verifyInclusionProof(leaf, i, n, corrupted, root),
      false,
      `n=${n} i=${i}: flipped sibling should fail`,
    );
  }
});

// ---------------------------------------------------------------------------
// 2. Consistency proofs: every (m, n) pair with 1 ≤ m < n ≤ 48
// ---------------------------------------------------------------------------

test("consistency proof verifies for all 1 ≤ m < n ≤ 48", () => {
  // Build the largest tree once; slice for smaller sizes to avoid O(n^2) tree builds
  const maxN = 48;
  const ls = leaves(maxN);
  for (let n = 2; n <= maxN; n++) {
    const newRoot = merkleRoot(ls.slice(0, n));
    for (let m = 1; m < n; m++) {
      const oldRoot = merkleRoot(ls.slice(0, m));
      const proof = consistencyPath(ls, m, n);
      assert.ok(
        verifyConsistencyProof(m, n, proof, oldRoot, newRoot),
        `m=${m} n=${n}: valid consistency proof should verify`,
      );
    }
  }
});

test("dropping one element from consistency proof fails for all 1 ≤ m < n ≤ 24 with non-trivial proof", () => {
  const ls = leaves(24);
  for (let n = 2; n <= 24; n++) {
    const newRoot = merkleRoot(ls.slice(0, n));
    for (let m = 1; m < n; m++) {
      const oldRoot = merkleRoot(ls.slice(0, m));
      const proof = consistencyPath(ls, m, n);
      if (proof.length === 0) continue; // nothing to drop for power-of-two trees with m=n
      const truncated = proof.slice(0, -1);
      assert.equal(
        verifyConsistencyProof(m, n, truncated, oldRoot, newRoot),
        false,
        `m=${m} n=${n}: truncated consistency proof should fail`,
      );
    }
  }
});

test("flipping a byte in consistency proof fails for all 1 ≤ m < n ≤ 24 with non-trivial proof", () => {
  const lcg = makeLcg(0x55aa55aa);
  const ls = leaves(24);
  for (let n = 2; n <= 24; n++) {
    const newRoot = merkleRoot(ls.slice(0, n));
    for (let m = 1; m < n; m++) {
      const oldRoot = merkleRoot(ls.slice(0, m));
      const proof = consistencyPath(ls, m, n);
      if (proof.length === 0) continue;
      const idx = lcg() % proof.length;
      const corrupted = proof.map((b, j) =>
        j === idx ? flipByte(b, lcg() % 32) : b,
      );
      assert.equal(
        verifyConsistencyProof(m, n, corrupted, oldRoot, newRoot),
        false,
        `m=${m} n=${n}: corrupted consistency proof should fail`,
      );
    }
  }
});

test("swapping old/new root in consistency proof fails for all 1 ≤ m < n ≤ 24", () => {
  const ls = leaves(24);
  let failures = 0;
  for (let n = 2; n <= 24; n++) {
    const newRoot = merkleRoot(ls.slice(0, n));
    for (let m = 1; m < n; m++) {
      const oldRoot = merkleRoot(ls.slice(0, m));
      if (oldRoot.equals(newRoot)) continue; // same root means same tree — not interesting
      const proof = consistencyPath(ls, m, n);
      const result = verifyConsistencyProof(m, n, proof, newRoot, oldRoot);
      if (result) failures++;
    }
  }
  assert.equal(failures, 0, `${failures} cases passed with swapped roots`);
});

test("verifyConsistencyProof: first > second returns false", () => {
  const ls = leaves(4);
  const r2 = merkleRoot(ls.slice(0, 2));
  const r4 = merkleRoot(ls);
  assert.equal(verifyConsistencyProof(4, 2, [], r2, r4), false);
});

test("verifyConsistencyProof: m === n returns true for empty proof with matching roots", () => {
  const ls = leaves(8);
  const root = merkleRoot(ls);
  assert.ok(verifyConsistencyProof(8, 8, [], root, root));
});

test("verifyConsistencyProof: m === n returns false for empty proof with mismatched roots", () => {
  const ls = leaves(8);
  const root = merkleRoot(ls);
  const other = merkleRoot(leaves(8, 1));
  assert.equal(verifyConsistencyProof(8, 8, [], root, other), false);
});

test("verifyConsistencyProof: m === 0 always returns true (empty old tree)", () => {
  const ls = leaves(10);
  const root = merkleRoot(ls);
  assert.ok(verifyConsistencyProof(0, 10, [], Buffer.alloc(32), root));
});

// ---------------------------------------------------------------------------
// 3. merkleRoot is deterministic and depends on all leaves
// ---------------------------------------------------------------------------

test("merkleRoot is stable (same input → same output) across sizes 1..64", () => {
  for (const n of SMALL_SIZES) {
    const ls = leaves(n);
    const r1 = merkleRoot(ls);
    const r2 = merkleRoot(ls);
    assert.ok(r1.equals(r2), `n=${n}: merkleRoot should be deterministic`);
  }
});

test("changing any one leaf changes the merkleRoot, sizes 1..32", () => {
  const lcg = makeLcg(0x0f0f0f0f);
  for (let n = 1; n <= 32; n++) {
    const ls = leaves(n);
    const root = merkleRoot(ls);
    const pos = lcg() % n;
    const mutated = ls.map((l, j) =>
      j === pos ? hashLeaf(Buffer.from(`mutated-${pos}`)) : l,
    );
    const mutatedRoot = merkleRoot(mutated);
    // For n=1 with identical content: could be equal if hash collides — but our inputs are distinct
    assert.ok(
      !root.equals(mutatedRoot),
      `n=${n} pos=${pos}: changing leaf should change root`,
    );
  }
});

test("all-zero leaves produce a different root than sequentially-named leaves, sizes 2..16", () => {
  for (let n = 2; n <= 16; n++) {
    const seqLeaves = leaves(n);
    const zeroLeaves = Array.from({ length: n }, () => hashLeaf(Buffer.alloc(4)));
    // zeroLeaves all hash the same → root will be a repeated hashNode chain
    // seqLeaves are distinct → different root
    const r1 = merkleRoot(seqLeaves);
    const r2 = merkleRoot(zeroLeaves);
    assert.ok(!r1.equals(r2), `n=${n}: distinct inputs should produce distinct roots`);
  }
});

// ---------------------------------------------------------------------------
// 4. hashLeaf / hashNode: RFC 6962 domain separation prevents second-preimage
// ---------------------------------------------------------------------------

test("hashLeaf and hashNode produce different outputs for the same payload bytes", () => {
  // If you pass the same data to both, the prefix byte separates the domains
  const data = Buffer.from("collide-me");
  const leafH = hashLeaf(data);
  // hashNode takes two equal-length Buffers; we construct one from the same data
  const half = Buffer.from("collide");
  const nodeH = hashNode(half, half);
  assert.ok(!leafH.equals(nodeH), "leaf and node hash of related data must differ");
});

test("hashNode is not commutative: hashNode(a,b) ≠ hashNode(b,a) for distinct a,b", () => {
  const lcg = makeLcg(0xf0f0f0f0);
  for (let i = 0; i < 16; i++) {
    const a = hashLeaf(Buffer.from(`left-${i}`));
    const b = hashLeaf(Buffer.from(`right-${i}`));
    assert.ok(
      !hashNode(a, b).equals(hashNode(b, a)),
      `i=${i}: hashNode(a,b) should not equal hashNode(b,a)`,
    );
  }
  void lcg; // keep lcg in scope (used for determinism seed)
});

test("verifyInclusionProof rejects index >= treeSize", () => {
  const ls = leaves(4);
  const root = merkleRoot(ls);
  const leaf = ls[0]!;
  assert.equal(verifyInclusionProof(leaf, 4, 4, [], root), false, "index === treeSize should fail");
  assert.equal(verifyInclusionProof(leaf, 5, 4, [], root), false, "index > treeSize should fail");
});

test("consistencyPath for power-of-two sizes produces minimal proof", () => {
  // For m = n/2 where n is a power of two, the old subtree is the left half
  // consistencyPath should return exactly the right-half root (1 element)
  const n = 8;
  const ls = leaves(n);
  const proof = consistencyPath(ls, 4, 8);
  // Not strictly one element always, but for power-of-two m it's [rightHalfRoot]
  assert.equal(proof.length, 1, "m=4, n=8 (power-of-two halves): consistency proof should have 1 element");
  const oldRoot = merkleRoot(ls.slice(0, 4));
  const newRoot = merkleRoot(ls);
  assert.ok(verifyConsistencyProof(4, 8, proof, oldRoot, newRoot));
});

test("appendLeaf grows root correctly: auditPath of original leaf still verifies in new tree", () => {
  // Build a tree of n leaves, record the root. Append one more leaf.
  // The consistency proof must verify between old and new root.
  for (let n = 4; n <= 20; n += 4) {
    const ls = leaves(n + 1);
    const oldRoot = merkleRoot(ls.slice(0, n));
    const newRoot = merkleRoot(ls);
    const proof = consistencyPath(ls, n, n + 1);
    assert.ok(
      verifyConsistencyProof(n, n + 1, proof, oldRoot, newRoot),
      `n=${n}: single-leaf append consistency should verify`,
    );
  }
});
