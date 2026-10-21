import { commit } from "./commit.ts";
import { verifyInclusion } from "./merkle.ts";
import type { DisclosureProof } from "./types.ts";

/**
 * Verify a selective-disclosure proof against the receipt's field_root.
 *
 * Recomputes the field commitment from the disclosed (salt, value) and checks
 * the Merkle inclusion path from that commitment up to field_root.
 *
 * Returns false (rather than throwing) on malformed input so callers can
 * treat verification as a total boolean function.
 */
export function verifyDisclosureProof(
  proof: DisclosureProof,
  fieldRoot: string,
): boolean {
  try {
    const leaf = commit(proof.disclosure.salt, proof.disclosure.value);
    return verifyInclusion(
      leaf,
      proof.merkle_path,
      proof.leaf_index,
      proof.leaf_count,
      fieldRoot,
    );
  } catch {
    return false;
  }
}
