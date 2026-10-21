/**
 * AAR compose callback — chain-walk warnings.
 *
 * Walks the `prev` chain from the receipt under verification and surfaces
 * any chain-integrity warnings via `walkAarChain`.
 */

import type { ComposeCallback } from "@dekimuhq/anchors-envelope";
import { buildAarChainIndex, walkAarChain } from "./chain.ts";
import type { AarBody, AarChainReceipt } from "./types.ts";
import { AAR_DEFAULT_DEPTH_LIMIT } from "./types.ts";

function projectChainReceipt(resolved: unknown): AarChainReceipt | null {
  if (resolved === null || typeof resolved !== "object") return null;
  const e = resolved as Record<string, unknown>;
  if (typeof e.id !== "string") return null;
  if (typeof e.iss !== "string") return null;
  if (typeof e.iat !== "string") return null;
  if (e.prev !== null && typeof e.prev !== "string") return null;
  if (e.body === null || typeof e.body !== "object") return null;
  const body = e.body as Record<string, unknown>;
  if (typeof body.event_type !== "string") return null;
  return {
    id: e.id,
    iss: e.iss,
    iat: e.iat,
    prev: e.prev as string | null,
    subject: typeof e.subject === "string" ? e.subject : null,
    body: e.body as AarBody,
  };
}

export const composeAar: ComposeCallback = async (input) => {
  const resolve = input.opts.resolveReceiptById;
  if (resolve === undefined) return { ok: true };

  const startReceipt = projectChainReceipt({
    id: input.envelope.id,
    iss: input.envelope.iss,
    iat: input.envelope.iat,
    prev: input.envelope.prev,
    subject: input.envelope.subject,
    body: input.envelope.body,
  });
  if (startReceipt === null) return { ok: true };

  const collected: AarChainReceipt[] = [startReceipt];
  const seen = new Set<string>([startReceipt.id]);
  let cursor: string | null = startReceipt.prev;
  let hopsTaken = 1;

  while (cursor !== null && hopsTaken < AAR_DEFAULT_DEPTH_LIMIT) {
    if (seen.has(cursor)) break;
    const resolved = await resolve(cursor);
    if (resolved === null || resolved === undefined) break;
    const projected = projectChainReceipt(resolved);
    if (projected === null) break;
    collected.push(projected);
    seen.add(projected.id);
    cursor = projected.prev;
    hopsTaken += 1;
  }

  const index = buildAarChainIndex(collected);
  const walk = walkAarChain(startReceipt.id, index);
  const warnings = walk.warnings.slice();
  return warnings.length > 0 ? { ok: true, warnings } : { ok: true };
};
