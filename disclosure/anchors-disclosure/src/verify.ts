import { verifyFieldCommit, verifyInclusion } from "@dekimuhq/anchors-envelope";
import { leafCommit } from "./tree.ts";
import type { DisclosurePresentation, DisclosureSchema, VerifyReason, VerifyResult } from "./types.ts";

export interface VerifyOptions {
  trustIssuer?: (iss_key: string) => boolean;
  schema?: DisclosureSchema;   // optional allowlist: every revealed path must be a declared leaf
}

function isPathInSchema(path: string, schema: DisclosureSchema): boolean {
  for (const spec of schema.leaves) {
    if (!spec.array) {
      if (path === spec.path) return true;
    } else if (path.startsWith(spec.path + "/")) {
      const idx = path.slice(spec.path.length + 1);
      if (/^\d+$/.test(idx)) return true;
    }
  }
  return false;
}

function isPresentationShape(p: unknown): p is DisclosurePresentation {
  if (p === null || typeof p !== "object") return false;
  const o = p as Record<string, unknown>;
  return (
    o.kind === "ar.disclosure.v1" &&
    typeof o.receipt_ref === "string" &&
    typeof o.field_root === "string" &&
    Number.isInteger(o.leaf_count) && (o.leaf_count as number) >= 1 &&
    Array.isArray(o.revealed) &&
    typeof o.field_commit === "object" && o.field_commit !== null
  );
}

/** Verify an ar.disclosure.v1 presentation. Total function — never throws. */
export function verifyPresentation(
  presentation: DisclosurePresentation,
  opts: VerifyOptions = {},
): VerifyResult {
  const fail = (...reasons: VerifyReason[]): VerifyResult => ({
    valid: false, revealed: {}, issuer: null, reasons,
  });

  try {
    if (!isPresentationShape(presentation)) return fail("malformed");
    const p = presentation;
    const fc = p.field_commit;

    // 1. Issuer-signed field_commit.
    if (!verifyFieldCommit(fc).valid) return fail("field_commit_sig_invalid");
    if (p.receipt_ref !== fc.id) return fail("field_commit_id_mismatch");
    if (p.field_root !== fc.field_root) return fail("field_root_mismatch");
    if (p.leaf_count !== fc.leaf_count) return fail("malformed");
    if (opts.trustIssuer && !opts.trustIssuer(fc.iss_key)) return fail("issuer_untrusted");

    // 2. Each revealed leaf: recompute commitment, verify Merkle inclusion to field_root.
    const revealed: Record<string, unknown> = {};
    for (const r of p.revealed) {
      if (
        r === null || typeof r !== "object" ||
        typeof r.path !== "string" || typeof r.salt !== "string" ||
        !Number.isInteger(r.leaf_index) || (r.leaf_index as number) < 0 ||
        !Array.isArray(r.merkle_path)
      ) return fail("malformed");

      if (opts.schema && !isPathInSchema(r.path, opts.schema)) return fail("malformed");

      const leaf = leafCommit(r.salt, r.path, r.value);
      const pathOk = verifyInclusion(leaf, r.merkle_path, r.leaf_index, fc.leaf_count, p.field_root);
      if (!pathOk) {
        // valid:false is authoritative; the reason is a best-effort diagnostic.
        // A structurally-wrong path (wrong length for the tree) is classified as a
        // path error; a correct-length path that still fails means the opening
        // (salt/value) didn't reproduce the committed leaf.
        const expectedDepth = Math.ceil(Math.log2(Math.max(2, fc.leaf_count)));
        return fail(r.merkle_path.length === expectedDepth ? "leaf_commit_mismatch" : "merkle_path_invalid");
      }
      revealed[r.path] = r.value;
    }

    return { valid: true, revealed, issuer: fc.iss_key, reasons: [] };
  } catch {
    return fail("malformed");
  }
}
