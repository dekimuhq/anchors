import { inclusionProof, buildTree } from "@dekimuhq/anchors-envelope";
import type { FieldCommitAttestation } from "@dekimuhq/anchors-envelope";
import { buildFieldTree } from "./tree.ts";
import type { DisclosureSchema, DisclosurePresentation, RevealedField, SaltSource } from "./types.ts";

export interface BuildPresentationInput {
  body: unknown;
  schema: DisclosureSchema;
  salts: SaltSource;
  fieldCommit: FieldCommitAttestation;
  reveal: string[];            // resolved leaf paths
  incl?: unknown;
}

/** Build an ar.disclosure.v1 presentation for a raw-value receipt (values in body). */
export function buildPresentation(input: BuildPresentationInput): DisclosurePresentation {
  const { body, schema, salts, fieldCommit, reveal, incl } = input;
  const { leaves, field_root, layout } = buildFieldTree(body, schema, salts);
  if (field_root !== fieldCommit.field_root) {
    throw new Error("buildPresentation: field_root mismatch vs field_commit");
  }
  if (fieldCommit.leaf_count !== leaves.length) {
    throw new Error("buildPresentation: field_commit.leaf_count != tree leaf count");
  }
  const tree = buildTree(leaves);
  const revealed: RevealedField[] = reveal.map((path) => {
    const entry = layout.find((l) => l.path === path);
    if (!entry) throw new Error(`buildPresentation: unknown reveal path ${path}`);
    return {
      path,
      value: entry.value,
      salt: salts.saltFor(path),
      merkle_path: inclusionProof(tree, entry.leaf_index),
      leaf_index: entry.leaf_index,
    };
  });
  return assemblePresentation({ fieldCommit, field_root, leaf_count: leaves.length, revealed, incl });
}

export interface AssembleInput {
  fieldCommit: FieldCommitAttestation;
  field_root: string;
  leaf_count: number;
  revealed: RevealedField[];
  incl?: unknown;
}

/** Lower-level assembler — used directly by adapters (e.g. ACR) that build their
 *  own per-field Merkle proofs and just need the presentation envelope. */
export function assemblePresentation(input: AssembleInput): DisclosurePresentation {
  const p: DisclosurePresentation = {
    kind: "ar.disclosure.v1",
    receipt_ref: input.fieldCommit.id,
    field_commit: input.fieldCommit,
    field_root: input.field_root,
    leaf_count: input.leaf_count,
    revealed: input.revealed,
  };
  if (input.incl !== undefined) p.incl = input.incl;
  return p;
}
