import { hashNode } from "./rfc6962.ts";

/** RFC 6962 §2.1 Merkle Tree Hash over an ordered list of leaf hashes. */
export function merkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) throw new Error("empty tree has no root");
  if (leaves.length === 1) {
    const leaf = leaves[0];
    if (!leaf) throw new Error("empty tree has no root");
    return leaf;
  }
  const k = largestPowerOfTwoSmallerThan(leaves.length);
  return hashNode(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

/** RFC 6962 §2.1.1 audit path (sibling hashes leaf→root). */
export function auditPath(leaves: Buffer[], index: number): Buffer[] {
  if (leaves.length <= 1) return [];
  const k = largestPowerOfTwoSmallerThan(leaves.length);
  if (index < k) {
    return [...auditPath(leaves.slice(0, k), index), merkleRoot(leaves.slice(k))];
  }
  return [...auditPath(leaves.slice(k), index - k), merkleRoot(leaves.slice(0, k))];
}

/** RFC 6962 §2.1.2 consistency proof between tree sizes m (old) and n (new). */
export function consistencyPath(leaves: Buffer[], m: number, n: number): Buffer[] {
  if (m <= 0 || m > n || n > leaves.length) throw new Error("invalid consistency range");
  if (m === n) return [];
  return subproof(leaves.slice(0, n), m, true);
}

function subproof(leaves: Buffer[], m: number, isComplete: boolean): Buffer[] {
  const n = leaves.length;
  if (m === n) return isComplete ? [] : [merkleRoot(leaves)];
  const k = largestPowerOfTwoSmallerThan(n);
  if (m <= k) {
    return [...subproof(leaves.slice(0, k), m, isComplete), merkleRoot(leaves.slice(k))];
  }
  return [...subproof(leaves.slice(k), m - k, false), merkleRoot(leaves.slice(0, k))];
}

function largestPowerOfTwoSmallerThan(n: number): number {
  let k = 1;
  while (k < n) k <<= 1;
  return k >> 1;
}
