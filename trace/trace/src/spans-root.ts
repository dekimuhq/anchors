/**
 * spans_root: an RFC-6962 Merkle root over per-span salted detail commits. One leaf
 * per span: leafCommit(salt(span_id), span_id, detail) — path-bound to span_id so a
 * span's detail cannot be relabelled. Leaf ORDER follows spans[] order (matches the
 * signed body). Reuses anchors primitives — no new crypto.
 */
import { leafCommit } from "@dekimuhq/anchors-disclosure";
import { buildTree } from "@dekimuhq/anchors-envelope";

export interface SpanSaltSource { saltFor(span_id: string): string; }
export interface SpansRootResult { spans_root: string; leaves: string[]; }

export function buildSpansRoot(
  spans: readonly { span_id: string }[],
  detail: Record<string, unknown>,
  salts: SpanSaltSource,
): SpansRootResult {
  const leaves = spans.map((s) => leafCommit(salts.saltFor(s.span_id), s.span_id, detail[s.span_id] ?? {}));
  const { root } = buildTree(leaves);
  return { spans_root: root, leaves };
}
