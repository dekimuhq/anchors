import { buildTree, commit, canonicalize } from "@dekimuhq/anchors-envelope";
import type { DisclosureSchema, SaltSource } from "./types.ts";

export interface LayoutEntry {
  path: string;        // resolved pointer
  value: unknown;
  leaf_index: number;
}

/** Resolve a single JSON-pointer token sequence against a value. Throws if absent. */
function pointerGet(root: unknown, pointer: string): unknown {
  if (pointer === "") return root;
  if (!pointer.startsWith("/")) throw new Error(`bad pointer: ${pointer}`);
  let cur: unknown = root;
  for (const rawTok of pointer.slice(1).split("/")) {
    const tok = rawTok.replace(/~1/g, "/").replace(/~0/g, "~");
    if (cur === null || typeof cur !== "object") throw new Error(`pointer miss: ${pointer}`);
    const obj = cur as Record<string, unknown>;
    if (!(tok in obj)) throw new Error(`pointer miss: ${pointer}`);
    cur = obj[tok];
  }
  return cur;
}

/** Expand the schema against the body into the ordered leaf layout. */
export function resolveLayout(body: unknown, schema: DisclosureSchema): LayoutEntry[] {
  const out: LayoutEntry[] = [];
  for (const spec of schema.leaves) {
    if (spec.array) {
      const arr = pointerGet(body, spec.path);
      if (!Array.isArray(arr)) throw new Error(`expected array at ${spec.path}`);
      arr.forEach((value, i) => out.push({ path: `${spec.path}/${i}`, value, leaf_index: out.length }));
    } else {
      out.push({ path: spec.path, value: pointerGet(body, spec.path), leaf_index: out.length });
    }
  }
  return out;
}

/** Leaf commitment for a field = commit(salt, canonicalize({ path, value })).
 *  The path is bound into the preimage so a leaf cannot be relabelled to a
 *  different field (field-relabel forgery defence). */
export function leafCommit(salt: string, path: string, value: unknown): string {
  return commit(salt, canonicalize({ path, value }));
}

export interface FieldTree {
  leaves: string[];          // per-field commitments (pre-merkle-prefix)
  field_root: string;
  layout: LayoutEntry[];
}

export function buildFieldTree(body: unknown, schema: DisclosureSchema, salts: SaltSource): FieldTree {
  const layout = resolveLayout(body, schema);
  const leaves = layout.map((e) => leafCommit(salts.saltFor(e.path), e.path, e.value));
  const { root } = buildTree(leaves);
  return { leaves, field_root: root, layout };
}
