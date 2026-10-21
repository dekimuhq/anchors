import { createHash } from "node:crypto";
import { canonicalize, verifyInclusion } from "./crypto-reexports.ts";
import type { ArrStateSnapshot } from "./types.ts";

export interface BatchDisclosureInput {
  snapshot: ArrStateSnapshot;
  leafIndex: number;
  proof: string[];
  root: string;
  totalLeaves: number;
}

export interface BatchDisclosureResult {
  valid: boolean;
  errors: string[];
}

function snapshotHash(snapshot: ArrStateSnapshot): string {
  const bytes = new TextEncoder().encode(canonicalize(snapshot));
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

export function verifyBatchDisclosure(input: BatchDisclosureInput): BatchDisclosureResult {
  const errors: string[] = [];
  if (input.leafIndex < 0 || input.leafIndex >= input.totalLeaves) {
    errors.push("leaf_index.out_of_bounds");
    return { valid: false, errors };
  }

  const leaf = snapshotHash(input.snapshot);
  const ok = verifyInclusion(leaf, input.proof, input.leafIndex, input.totalLeaves, input.root);
  if (!ok) errors.push("root.mismatch");
  return { valid: errors.length === 0, errors };
}
