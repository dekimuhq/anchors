/**
 * RFC 6962-style binary Merkle tree.
 *
 * Leaf hash: SHA-256(0x00 || leaf_bytes)
 * Node hash: SHA-256(0x01 || left || right)
 * Odd leaves: duplicate the last leaf at the level.
 *
 * All hashes encoded as "sha256:<hex>".
 */

import * as crypto from "node:crypto";

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export interface MerkleTree {
  root: string;
  levels: string[][];
  leafCount: number;
}

function parseHash(h: string): Buffer {
  if (!h.startsWith("sha256:")) throw new Error(`expected sha256: prefix`);
  const hex = h.slice(7);
  if (hex.length !== 64) throw new Error(`expected 64 hex chars`);
  return Buffer.from(hex, "hex");
}

function leafHash(leaf: string): string {
  const h = crypto.createHash("sha256");
  h.update(LEAF_PREFIX);
  h.update(parseHash(leaf));
  return `sha256:${h.digest("hex")}`;
}

function nodeHash(left: string, right: string): string {
  const h = crypto.createHash("sha256");
  h.update(NODE_PREFIX);
  h.update(parseHash(left));
  h.update(parseHash(right));
  return `sha256:${h.digest("hex")}`;
}

export function buildTree(leaves: string[]): MerkleTree {
  if (leaves.length === 0) throw new Error("buildTree: empty leaves");

  const level0: string[] = leaves.map(leafHash);
  const levels: string[][] = [level0];

  let current = level0;
  while (current.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i]!;
      const right = i + 1 < current.length ? current[i + 1]! : left;
      next.push(nodeHash(left, right));
    }
    levels.push(next);
    current = next;
  }

  return { root: current[0]!, levels, leafCount: leaves.length };
}

export function inclusionProof(tree: MerkleTree, leafIndex: number): string[] {
  if (leafIndex < 0 || leafIndex >= tree.leafCount) {
    throw new Error(`inclusionProof: index ${leafIndex} out of range`);
  }
  const proof: string[] = [];
  let idx = leafIndex;
  for (let depth = 0; depth < tree.levels.length - 1; depth++) {
    const level = tree.levels[depth]!;
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    proof.push(siblingIdx < level.length ? level[siblingIdx]! : level[idx]!);
    idx = Math.floor(idx / 2);
  }
  return proof;
}

export function verifyInclusion(
  leaf: string,
  proof: string[],
  leafIndex: number,
  leafCount: number,
  expectedRoot: string,
): boolean {
  if (leafIndex < 0 || leafIndex >= leafCount) return false;
  let node = leafHash(leaf);
  let idx = leafIndex;
  for (const sibling of proof) {
    if (idx % 2 === 0) {
      node = nodeHash(node, sibling);
    } else {
      node = nodeHash(sibling, node);
    }
    idx = Math.floor(idx / 2);
  }
  return node === expectedRoot;
}
