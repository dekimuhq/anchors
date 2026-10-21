import * as crypto from "node:crypto";

export function sha256(b: Buffer): Buffer {
  return crypto.createHash("sha256").update(b).digest();
}

/** RFC 6962 §2.1 leaf hash: SHA-256(0x00 ‖ data). */
export function hashLeaf(data: Buffer): Buffer {
  return sha256(Buffer.concat([Buffer.of(0x00), data]));
}

/** RFC 6962 §2.1 node hash: SHA-256(0x01 ‖ left ‖ right). */
export function hashNode(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.concat([Buffer.of(0x01), left, right]));
}

/** RFC 6962 §2.1.1 inclusion-proof verification (recompute root from leaf + audit path). */
export function verifyInclusionProof(
  leaf: Buffer,
  index: number,
  treeSize: number,
  path: Buffer[],
  expectedRoot: Buffer,
): boolean {
  if (index >= treeSize) return false;
  let hash = leaf;
  let fn = index;
  let sn = treeSize - 1;
  for (const sibling of path) {
    if (fn === sn || (fn & 1) === 1) {
      hash = hashNode(sibling, hash);
      while (!((fn & 1) === 1 || fn === 0)) { fn >>= 1; sn >>= 1; }
    } else {
      hash = hashNode(hash, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return fn === 0 && hash.equals(expectedRoot);
}

/** RFC 6962 §2.1.2 consistency-proof verification between two tree sizes. */
export function verifyConsistencyProof(
  first: number,
  second: number,
  proof: Buffer[],
  firstRoot: Buffer,
  secondRoot: Buffer,
): boolean {
  if (first > second) return false;
  if (first === second) return proof.length === 0 && firstRoot.equals(secondRoot);
  if (first === 0) return true; // empty old tree is consistent with anything
  let node = proof.slice();
  // isPowerOfTwo(first): the old root is implicit, prepend it
  let fn = first - 1;
  let sn = second - 1;
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }
  let fr = (fn !== 0) ? node.shift()! : firstRoot;
  let sr = fr;
  for (const c of node) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = hashNode(c, fr);
      sr = hashNode(c, sr);
      while (!((fn & 1) === 1 || fn === 0)) { fn >>= 1; sn >>= 1; }
    } else {
      sr = hashNode(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return fr.equals(firstRoot) && sr.equals(secondRoot) && sn === 0;
}
