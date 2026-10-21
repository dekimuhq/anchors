/**
 * composeAer — compose-warnings callback for AER (spec §7).
 *
 * Wires the AER family's `compose` slot in `aerFamily` (see family.ts).
 * Invoked by the envelope's `buildVerifyReceipt` pipeline as the final step
 * after profile dispatch when verifying a receipt. Returns
 * `{ ok: true, warnings: [...] }` with zero or more informational warning
 * codes; warnings flow onto `FamilyVerifyResult.warnings` without poisoning
 * `signature_valid`.
 *
 * ── Conformity receipts ────────────────────────────────────────────────────
 *
 * When `event_type === "conformity"` and `opts.resolveReceiptById` is
 * supplied, the callback walks the `prev` chain from the receipt under
 * verification back to the chain head, builds an `AerChainIndex`, then runs
 * `walkAerConformityChain` and collects its `warnings` array.
 * `hard_invalid_reasons` are intentionally omitted — chain-conformance
 * hard-fail is the responsibility of direct `walkAerConformityChain` callers;
 * compose only surfaces informational diagnostics.
 *
 * ── Transparency receipts ──────────────────────────────────────────────────
 *
 * When `event_type === "transparency"` and `opts.resolveReceiptById` is
 * supplied, the callback resolves `body.conformity_receipt_hash` to a
 * conformity receipt and runs `checkTransparencyBacking`. If the backing
 * check fails, a `aer.transparency_not_backed:<reason>` warning is surfaced.
 *
 * ── No resolver ────────────────────────────────────────────────────────────
 *
 * When `opts.resolveReceiptById` is absent, compose is a no-op (returns
 * `{ ok: true }`). Chain-walk and backing warnings require a corpus.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/aer §7
 */

import type { ComposeCallback } from "@dekimuhq/anchors-envelope";
import {
  buildAerChainIndex,
  checkTransparencyBacking,
  walkAerConformityChain,
} from "./chain.ts";
import type { AerBody, AerChainReceipt, AerTransparencyBody } from "./types.ts";
import { AER_DEFAULT_DEPTH_LIMIT } from "./types.ts";

/**
 * Project an arbitrary resolved-envelope object onto the minimal
 * `AerChainReceipt` shape expected by `walkAerConformityChain`. Returns `null`
 * when the projection fails (missing/mistyped field) — callers treat this as a
 * dangling reference and abort the walk gracefully.
 *
 * AER does not have a `token_id` field. The `event_type` on the body is
 * validated to be one of the two AER event types.
 */
function projectChainReceipt(resolved: unknown): AerChainReceipt | null {
  if (resolved === null || typeof resolved !== "object") return null;
  const e = resolved as Record<string, unknown>;
  if (typeof e.id !== "string") return null;
  if (typeof e.iss !== "string") return null;
  if (typeof e.iat !== "string") return null;
  if (e.prev !== null && typeof e.prev !== "string") return null;
  if (e.body === null || typeof e.body !== "object") return null;
  const body = e.body as Record<string, unknown>;
  if (body.event_type !== "conformity" && body.event_type !== "transparency") return null;
  return {
    id: e.id,
    iss: e.iss,
    iat: e.iat,
    prev: e.prev as string | null,
    subject: typeof e.subject === "string" ? e.subject : null,
    body: e.body as AerBody,
  };
}

/**
 * compose-warnings callback for AER. See module docstring for the warning
 * surface.
 *
 * Pure relative to resolvers — never throws. The factory pipeline wraps any
 * throw in `compose_threw:<msg>` per `ComposeResult` contract.
 */
export const composeAer: ComposeCallback = async (input) => {
  // No resolver → no-op (chain-walk and backing warnings require a corpus).
  const resolve = input.opts.resolveReceiptById;
  if (resolve === undefined) {
    return { ok: true };
  }

  // Determine the event_type from the body.
  const body = input.envelope.body as Record<string, unknown> | null;
  if (body === null || typeof body !== "object") {
    return { ok: true };
  }
  const eventType = body.event_type;

  // ── Transparency path ──────────────────────────────────────────────────────

  if (eventType === "transparency") {
    const tBody = body as unknown as AerTransparencyBody;
    const conformityHash = tBody.conformity_receipt_hash;
    if (typeof conformityHash !== "string") {
      return { ok: true };
    }

    // Resolve the conformity receipt referenced by hash.
    const conformityResolved = await resolve(conformityHash);
    if (conformityResolved === null || conformityResolved === undefined) {
      return { ok: true, warnings: ["aer.transparency_not_backed:conformity_not_found"] };
    }

    const conformityReceipt = projectChainReceipt(conformityResolved);
    if (conformityReceipt === null) {
      return { ok: true, warnings: ["aer.transparency_not_backed:conformity_not_found"] };
    }

    // Build the start receipt for checkTransparencyBacking.
    const tReceipt = projectChainReceipt({
      id: input.envelope.id,
      iss: input.envelope.iss,
      iat: input.envelope.iat,
      prev: input.envelope.prev,
      subject: input.envelope.subject,
      body: input.envelope.body,
    });
    if (tReceipt === null) {
      return { ok: true };
    }

    const backing = checkTransparencyBacking(
      tReceipt,
      (hash) => (hash === conformityHash ? conformityReceipt : undefined),
    );

    if (!backing.backed) {
      const reason = backing.reason ?? "unknown";
      return { ok: true, warnings: [`aer.transparency_not_backed:${reason}`] };
    }

    return { ok: true };
  }

  // ── Conformity chain-walk path ─────────────────────────────────────────────

  if (eventType !== "conformity") {
    // Unknown event_type — skip chain-walk.
    return { ok: true };
  }

  // Project the receipt under verification onto the chain receipt shape.
  const startReceipt = projectChainReceipt({
    id: input.envelope.id,
    iss: input.envelope.iss,
    iat: input.envelope.iat,
    prev: input.envelope.prev,
    subject: input.envelope.subject,
    body: input.envelope.body,
  });
  if (startReceipt === null) {
    return { ok: true };
  }

  const collected: AerChainReceipt[] = [startReceipt];
  const seen = new Set<string>([startReceipt.id]);
  let cursor: string | null = startReceipt.prev;
  let hopsTaken = 1;

  while (cursor !== null && hopsTaken < AER_DEFAULT_DEPTH_LIMIT) {
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

  const index = buildAerChainIndex(collected);
  const walk = walkAerConformityChain(startReceipt.id, index);

  // Surface both informational warnings and hard_invalid_reasons as advisory
  // warnings. Compose never poisons signature_valid — hard-fail enforcement is
  // the responsibility of direct walkAerConformityChain callers.
  const warnings = [...walk.warnings, ...walk.hard_invalid_reasons];
  return warnings.length > 0 ? { ok: true, warnings } : { ok: true };
};
