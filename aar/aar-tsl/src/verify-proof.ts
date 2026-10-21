/**
 * Standalone TSL inclusion proof verifier.
 *
 * No network, no state. Takes a TslProofBundle + expected root,
 * returns whether the proof is valid.
 */

import { verifyInclusion } from "./merkle.ts";
import type { TslProofBundle } from "./types.ts";

/**
 * Verify that a TSL proof bundle is valid against a trusted tree head root.
 *
 * Brute-forces the leaf index (tree_size is small, ~1K max).
 */
export function verifyTslInclusionProof(
  bundle: TslProofBundle,
  expectedRoot: string,
): boolean {
  if (bundle.tsl_signed_tree_head_root !== expectedRoot) return false;
  if (bundle.tsl_tree_size <= 0) return false;
  if (bundle.tsl_inclusion_proof.length === 0 && bundle.tsl_tree_size > 1) return false;

  for (let i = 0; i < bundle.tsl_tree_size; i++) {
    if (
      verifyInclusion(
        bundle.tsl_entry_hash,
        bundle.tsl_inclusion_proof,
        i,
        bundle.tsl_tree_size,
        expectedRoot,
      )
    ) {
      return true;
    }
  }
  return false;
}
