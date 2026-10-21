import {
  commit,
  buildTree,
  inclusionProof,
  type ACRReceipt,
  type DisclosureProof,
} from "../index.ts";
import type { SaltBundle } from "./mint.ts";

interface BuildDisclosureInput {
  receipt: ACRReceipt;
  salts: SaltBundle;
  /** Which field to disclose. One of: "sub_commit", "policy_hash", or "purposes[N]". */
  field: string;
  value: string;
}

/**
 * Build a selective-disclosure proof for one field of a receipt.
 *
 * Layout convention (matches `mint.ts`):
 *  leaf 0           = sub_commit
 *  leaf 1..purposes = purposes[i]
 *  leaf last        = policy_hash
 */
export function buildDisclosureProof(input: BuildDisclosureInput): DisclosureProof {
  const { receipt, salts, field, value } = input;
  const totalLeaves = 1 + receipt.purposes.length + 1;

  let leafIndex: number;
  let salt: string;

  if (field === "sub_commit") {
    leafIndex = 0;
    salt = salts.sub_commit;
  } else if (field === "policy_hash") {
    leafIndex = totalLeaves - 1;
    salt = salts.policy_hash;
  } else if (field.startsWith("purposes[") && field.endsWith("]")) {
    const idx = Number(field.slice("purposes[".length, -1));
    if (!Number.isInteger(idx) || idx < 0 || idx >= receipt.purposes.length) {
      throw new Error(`buildDisclosureProof: bad purposes index in ${field}`);
    }
    leafIndex = 1 + idx;
    salt = salts.purposes[idx]!;
  } else {
    throw new Error(`buildDisclosureProof: unsupported field "${field}"`);
  }

  // Sanity: recompute the commitment and confirm it matches what's in the receipt.
  const recomputed = commit(salt, value);
  const leaves = [receipt.sub_commit, ...receipt.purposes, receipt.policy_hash];
  if (recomputed !== leaves[leafIndex]) {
    throw new Error("buildDisclosureProof: commitment mismatch (wrong value or salt for field)");
  }

  const tree = buildTree(leaves);
  return {
    disclosure: { field, value, salt },
    merkle_path: inclusionProof(tree, leafIndex),
    leaf_index: leafIndex,
    leaf_count: leaves.length,
  };
}
