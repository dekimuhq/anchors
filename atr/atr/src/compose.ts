/**
 * composeAtr — compose-warnings callback for ATR (spec §7).
 *
 * Wires the ATR family's `compose` slot in `atrFamily` (see family.ts).
 * Invoked by the envelope's `buildVerifyReceipt` pipeline as the final step
 * after profile dispatch when verifying a receipt. Returns
 * `{ ok: true, warnings: [...] }` with zero or more informational warning
 * codes; warnings flow onto `FamilyVerifyResult.warnings` without poisoning
 * `signature_valid`.
 *
 * ── Chain-walk warnings ────────────────────────────────────────────────────
 *
 * Surfaced when the caller supplies `opts.resolveReceiptById`. The callback
 * walks the `prev` chain from the receipt under verification back to the
 * chain head, builds an `AtrChainIndex`, then runs `walkAtrArrangementChain`
 * and collects its `warnings` array. The `hard_invalid_reasons` array is
 * intentionally ignored — chain-conformance hard-fail is the responsibility
 * of direct `walkAtrArrangementChain` callers; compose only surfaces
 * informational diagnostics, never poisons `signature_valid`. Pattern mirrors
 * AIR Phase 4B-2 (`composeAir` in `air-verifier/src/compose.ts`).
 *
 * When `opts.resolveReceiptById` is absent, compose is a no-op.
 *
 * ── Event-type gating ──────────────────────────────────────────────────────
 *
 * Only arrangement and suspension events participate in a prev-linked chain.
 * Transfer and tia events are standalone leaves — no chain walk is performed
 * for them; compose returns `{ ok: true }` immediately.
 *
 * ── Walk semantics ─────────────────────────────────────────────────────────
 *
 * The walker follows `prev` from the envelope under verification backward,
 * capping at `ATR_DEFAULT_DEPTH_LIMIT` hops. The resolver is called once
 * per hop until either:
 *
 *   1. The walker reaches the chain head (`prev === null`).
 *   2. The resolver returns `null` / `undefined` for a `prev` that is
 *      non-null (dangling reference — chain walk aborts).
 *   3. The depth limit is hit.
 *   4. The resolver throws — caught by the envelope pipeline and surfaced
 *      as `compose_threw:<msg>`.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/atr §7
 */

import type { ComposeCallback } from "@dekimuhq/anchors-envelope";
import { buildAtrChainIndex, walkAtrArrangementChain } from "./chain.ts";
import type { AtrBody, AtrChainReceipt } from "./types.ts";
import { ATR_DEFAULT_DEPTH_LIMIT } from "./types.ts";

// ── Event types that participate in prev-linked chains ─────────────────────────

const CHAINED_EVENT_TYPES = new Set<string>(["arrangement", "suspension"]);

/**
 * Project an arbitrary resolved-envelope object onto the minimal
 * `AtrChainReceipt` shape expected by `walkAtrArrangementChain`. Returns
 * `null` when the projection fails (missing/mistyped field) — callers treat
 * this as a dangling reference and abort the walk gracefully.
 */
function projectChainReceipt(resolved: unknown): AtrChainReceipt | null {
  if (resolved === null || typeof resolved !== "object") return null;
  const e = resolved as Record<string, unknown>;
  if (typeof e.id !== "string") return null;
  if (typeof e.iss !== "string") return null;
  if (typeof e.iat !== "string") return null;
  if (e.prev !== null && typeof e.prev !== "string") return null;
  if (e.body === null || typeof e.body !== "object") return null;
  const body = e.body as Record<string, unknown>;
  if (typeof body.event_type !== "string") return null;
  const profile =
    typeof e.profile === "string"
      ? e.profile
      : typeof body.profile === "string"
        ? body.profile
        : "";
  return {
    id: e.id,
    iss: e.iss,
    iat: e.iat,
    prev: e.prev as string | null,
    subject: typeof e.subject === "string" ? e.subject : null,
    profile,
    body: e.body as AtrBody,
  };
}

/**
 * compose-warnings callback for ATR. See module docstring for the
 * warning surface.
 *
 * Pure relative to resolvers — never throws. The factory pipeline wraps any
 * throw in `compose_threw:<msg>` per `ComposeResult` contract.
 */
export const composeAtr: ComposeCallback = async (input) => {
  // No resolver → no-op (chain-walk warnings require a corpus).
  const resolve = input.opts.resolveReceiptById;
  if (resolve === undefined) {
    return { ok: true };
  }

  // Project the receipt under verification onto the chain receipt shape.
  // If projection fails, skip chain-walk entirely — the single-hop verifier
  // upstream will already have caught structural problems.
  const startReceipt = projectChainReceipt({
    id: input.envelope.id,
    iss: input.envelope.iss,
    iat: input.envelope.iat,
    prev: input.envelope.prev,
    subject: input.envelope.subject,
    // `profile` is not exposed on ComposeInput.envelope; read from body if present.
    body: input.envelope.body,
  });
  if (startReceipt === null) {
    return { ok: true };
  }

  // Transfer and TIA events are standalone leaves — no chain walk.
  if (!CHAINED_EVENT_TYPES.has(startReceipt.body.event_type)) {
    return { ok: true };
  }

  const collected: AtrChainReceipt[] = [startReceipt];
  const seen = new Set<string>([startReceipt.id]);
  let cursor: string | null = startReceipt.prev;
  let hopsTaken = 1;

  while (cursor !== null && hopsTaken < ATR_DEFAULT_DEPTH_LIMIT) {
    if (seen.has(cursor)) {
      // Cycle — the walker will also detect this; stop fetching here.
      break;
    }
    const resolved = await resolve(cursor);
    if (resolved === null || resolved === undefined) {
      // Dangling reference — keep what we have.
      break;
    }
    const projected = projectChainReceipt(resolved);
    if (projected === null) {
      // Resolver returned a non-conforming shape — same handling as dangling.
      break;
    }
    collected.push(projected);
    seen.add(projected.id);
    cursor = projected.prev;
    hopsTaken += 1;
  }

  const index = buildAtrChainIndex(collected);
  const walk = walkAtrArrangementChain(startReceipt.id, index);

  const warnings = walk.warnings.slice();
  return warnings.length > 0 ? { ok: true, warnings } : { ok: true };
};
