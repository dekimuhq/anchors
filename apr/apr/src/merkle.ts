/**
 * Reference Merkle scheme used by APR v1 conformance vectors. See
 * `apr-spec/conformance/test-vectors/SCHEME.md` for the prose definition.
 *
 *   leaf_i      = sha256(claimId_i UTF-8 bytes)
 *   parent      = sha256(left || right)            // raw 32-byte concat
 *   odd level   = duplicate the trailing node
 *   rootHash    = lowercase hex of the final 32 bytes
 *   ordering    = claim ids sorted ascending (UTF-8 byte order)
 *
 * v1 of the spec leaves the on-the-wire inclusion-proof format
 * verifier-defined (§7.3). This implementation rebuilds the root from a
 * caller-supplied id set; production verifiers backed by sparse-tree or
 * compact-proof formats would use a different code path here.
 */

import * as crypto from "node:crypto";

function sha256(b: Buffer): Buffer {
  return crypto.createHash("sha256").update(b).digest();
}

export function computeMerkleRoot(claimIds: readonly string[]): string {
  if (claimIds.length === 0) return "0".repeat(64);
  const sorted = [...claimIds].sort();
  let level: Buffer[] = sorted.map((id) => sha256(Buffer.from(id, "utf8")));
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i]!;
      const b = level[i + 1] ?? a;
      next.push(sha256(Buffer.concat([a, b])));
    }
    level = next;
  }
  return level[0]!.toString("hex");
}
