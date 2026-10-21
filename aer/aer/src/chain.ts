/**
 * AER chain walker (spec §7).
 *
 * Two concerns:
 *   1. Conformity chain — linear `prev` chain of conformity receipts.
 *      Root has `prev=null`. Latest in chain = current in-force conformity.
 *      Bounded by `valid_until`.
 *   2. Transparency backing — a transparency receipt is "backed" iff it
 *      references an in-force conformity receipt at the time of the
 *      interaction.
 *
 * Chain rules:
 *   1. Chain integrity — cycles, dangling prev, non-conformity node
 *   2. Issuer consistency
 *   3. All chain members must be conformity event_type
 */

import type {
  AerBody,
  AerChainReceipt,
  AerChainWalkResult,
  AerConformityBody,
  AerTransparencyBody,
} from "./types.ts";
import {
  AER_DEFAULT_DEPTH_LIMIT,
  AER_DEPTH_LIMIT_MAX,
  AER_DEPTH_LIMIT_MIN,
} from "./types.ts";

// ── Index ─────────────────────────────────────────────────────────────────────

export interface AerChainIndex {
  readonly byId: ReadonlyMap<string, AerChainReceipt>;
}

/**
 * Build a lookup index keyed by receipt `id`.
 * Duplicate IDs keep the first occurrence.
 */
export function buildAerChainIndex(
  receipts: readonly AerChainReceipt[],
): AerChainIndex {
  const byId = new Map<string, AerChainReceipt>();
  for (const r of receipts) {
    if (!byId.has(r.id)) byId.set(r.id, r);
  }
  return { byId };
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface AerChainWalkOptions {
  /** Max hops. Clamped to [AER_DEPTH_LIMIT_MIN, AER_DEPTH_LIMIT_MAX]. */
  depthLimit?: number;
}

function clampDepth(d: number | undefined): number {
  const v = d ?? AER_DEFAULT_DEPTH_LIMIT;
  if (v < AER_DEPTH_LIMIT_MIN) return AER_DEPTH_LIMIT_MIN;
  if (v > AER_DEPTH_LIMIT_MAX) return AER_DEPTH_LIMIT_MAX;
  return v;
}

// ── Conformity chain walker ───────────────────────────────────────────────────

/**
 * Walk the conformity chain from `startId` backward through `prev`.
 *
 * Rules enforced:
 *   1. Chain integrity — cycles → `aer.chain_cycle_detected`;
 *      dangling / depth-exceeded → `aer.chain_prev_unresolved`.
 *   2. All chain members must be `event_type === "conformity"` —
 *      mixed-event chains are HARD invalid (`aer.non_conformity_in_chain`).
 *   3. Issuer consistency — all members must share the same `iss`
 *      (`aer.issuer_inconsistent`).
 */
export function walkAerConformityChain(
  startId: string,
  index: AerChainIndex,
  opts?: AerChainWalkOptions,
): AerChainWalkResult {
  const limit = clampDepth(opts?.depthLimit);
  const hard: string[] = [];
  const warn: string[] = [];

  const start = index.byId.get(startId);
  if (start === undefined) {
    return { ok: false, hard_invalid_reasons: ["aer.receipt_not_found"], warnings: [] };
  }

  const hops: AerChainReceipt[] = [];
  const visited = new Set<string>();
  let cursor: string | null = startId;
  let cycle = false;
  let dangling = false;

  while (cursor !== null) {
    if (visited.has(cursor)) {
      cycle = true;
      break;
    }
    visited.add(cursor);

    const r = index.byId.get(cursor);
    if (r === undefined) {
      dangling = true;
      break;
    }

    hops.push(r);

    if (hops.length > limit) {
      // Exceeded depth limit without reaching a root — treat as dangling.
      dangling = true;
      break;
    }

    cursor = r.prev;
  }

  if (cycle) hard.push("aer.chain_cycle_detected");
  if (dangling) hard.push("aer.chain_prev_unresolved");

  if (hard.length > 0) {
    return { ok: false, hard_invalid_reasons: hard, warnings: warn };
  }

  // Rule 2: all chain members must be conformity event_type
  for (const r of hops) {
    if (r.body.event_type !== "conformity") {
      hard.push("aer.non_conformity_in_chain");
      break;
    }
  }

  // Rule 3: issuer consistency — walk oldest-first
  const oldestFirst = [...hops].reverse();
  const firstIss = oldestFirst[0]?.iss;
  if (firstIss !== undefined) {
    for (const r of oldestFirst) {
      if (r.iss !== firstIss) {
        hard.push("aer.issuer_inconsistent");
        break;
      }
    }
  }

  return { ok: hard.length === 0, hard_invalid_reasons: hard, warnings: warn };
}

// ── Transparency backing check (spec §7.2) ────────────────────────────────────

export interface TransparencyBackingResult {
  backed: boolean;
  reason?: string;
}

/**
 * Check whether a transparency receipt is backed by an in-force conformity
 * receipt at the time of the interaction.
 *
 * Spec §7.2 rules:
 *   - T must have `event_type === "transparency"`.
 *   - T.body.conformity_receipt_hash must resolve to a conformity receipt C.
 *   - C.body.event_type must be `"conformity"`.
 *   - C.body.valid_from ≤ T.body.interaction_window_start (conformity already valid).
 *   - C.body.valid_until is null (open-ended) OR
 *     C.body.valid_until > T.body.interaction_window_start (not yet expired).
 */
export function checkTransparencyBacking(
  transparencyReceipt: AerChainReceipt,
  resolveConformity: (hash: string) => AerChainReceipt | undefined,
): TransparencyBackingResult {
  const tBody = transparencyReceipt.body;
  if (tBody.event_type !== "transparency") {
    return { backed: false, reason: "not_transparency" };
  }

  const tBodyT = tBody as AerTransparencyBody;
  const conformityHash = tBodyT.conformity_receipt_hash;
  const conformity = resolveConformity(conformityHash);
  if (conformity === undefined) {
    return { backed: false, reason: "conformity_not_found" };
  }

  const cBody = conformity.body;
  if (cBody.event_type !== "conformity") {
    return { backed: false, reason: "referenced_not_conformity" };
  }

  const cBodyC = cBody as AerConformityBody;

  const interactionMs = Date.parse(tBodyT.interaction_window_start);
  const fromMs = Date.parse(cBodyC.valid_from);

  if (Number.isNaN(interactionMs) || Number.isNaN(fromMs)) {
    return { backed: false, reason: "invalid_timestamps" };
  }

  if (fromMs > interactionMs) {
    return { backed: false, reason: "conformity_not_yet_valid" };
  }

  if (cBodyC.valid_until !== null) {
    const untilMs = Date.parse(cBodyC.valid_until);
    if (!Number.isNaN(untilMs) && untilMs <= interactionMs) {
      return { backed: false, reason: "conformity_expired" };
    }
  }

  return { backed: true };
}

// Re-export AerBody for callers that import chain helpers.
export type { AerBody, AerChainReceipt, AerChainWalkResult };
