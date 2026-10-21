/**
 * AAR chain walker (spec §7).
 *
 * AAR has the simplest chain semantics in the family:
 *   - issuance (chain head, prev=null)
 *   - optional revocation (prev → issuance id, at most one)
 *
 * 5 validation rules:
 *   1. Prev chain integrity — cycles, dangling prev, non-issuance head
 *   2. Issuer consistency
 *   3. Subject consistency
 *   4. At most one revocation
 *   5. Revocation must reference an issuance
 */

import type {
  AarChainReceipt,
  AarChainWalkResult,
} from "./types.ts";
import {
  AAR_DEFAULT_DEPTH_LIMIT,
  AAR_DEPTH_LIMIT_MAX,
  AAR_DEPTH_LIMIT_MIN,
} from "./types.ts";

// ── Index ─────────────────────────────────────────────────────────────────────

export interface AarChainIndex {
  readonly byId: ReadonlyMap<string, AarChainReceipt>;
}

/**
 * Build a lookup index keyed by envelope `id`.
 * Duplicate envelope IDs keep the first occurrence.
 */
export function buildAarChainIndex(
  receipts: readonly AarChainReceipt[],
): AarChainIndex {
  const byId = new Map<string, AarChainReceipt>();
  for (const r of receipts) {
    if (!byId.has(r.id)) byId.set(r.id, r);
  }
  return { byId };
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface AarChainWalkOptions {
  /** Max hops. Clamped to [AAR_DEPTH_LIMIT_MIN, AAR_DEPTH_LIMIT_MAX]. */
  depthLimit?: number;
}

function clampDepth(d: number | undefined): number {
  const v = d ?? AAR_DEFAULT_DEPTH_LIMIT;
  if (v < AAR_DEPTH_LIMIT_MIN) return AAR_DEPTH_LIMIT_MIN;
  if (v > AAR_DEPTH_LIMIT_MAX) return AAR_DEPTH_LIMIT_MAX;
  return v;
}

// ── Walker ────────────────────────────────────────────────────────────────────

/**
 * Walk from `startId` backward through `prev`, validating the 5 AAR chain
 * rules:
 *
 *  1. Prev chain integrity — cycles (`aar.chain_cycle_detected`),
 *     dangling prev (`aar.chain_prev_unresolved`), chain head that isn't
 *     an issuance (`aar.chain_head_not_issuance`). Depth limit applies.
 *  2. Issuer consistency (`aar.issuer_inconsistent`)
 *  3. Subject consistency (`aar.subject_inconsistent`)
 *  4. At most one revocation (`aar.multiple_revocations`)
 *  5. Revocation must reference an issuance (`aar.revocation_references_non_issuance`)
 *
 * Structural failures (rule 1) cause early bail — rules 2–5 only run on a
 * clean chain.
 */
export function walkAarChain(
  startId: string,
  index: AarChainIndex,
  opts?: AarChainWalkOptions,
): AarChainWalkResult {
  const limit = clampDepth(opts?.depthLimit);
  const hard: string[] = [];
  const warn: string[] = [];

  const start = index.byId.get(startId);
  if (start === undefined) {
    return { ok: false, hard_invalid_reasons: ["aar.receipt_not_found"], warnings: [] };
  }

  // ── Rule 1: Walk prev chain ────────────────────────────────────────────────

  const hops: AarChainReceipt[] = [];
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
      // exceeded depth without reaching head — treat as dangling
      dangling = true;
      break;
    }

    cursor = r.prev;
  }

  if (cycle) {
    hard.push("aar.chain_cycle_detected");
  }
  if (dangling) {
    hard.push("aar.chain_prev_unresolved");
  }

  // Check chain head that isn't an issuance (prev=null but event_type !== "issuance")
  const head = hops[hops.length - 1];
  if (
    head !== undefined &&
    !cycle &&
    !dangling &&
    head.prev === null &&
    head.body.event_type !== "issuance"
  ) {
    hard.push("aar.chain_head_not_issuance");
  }

  // Structural failures — bail before cross-event rules
  if (hard.length > 0) {
    return { ok: false, hard_invalid_reasons: hard, warnings: warn };
  }

  // Oldest → newest for cross-event rules
  const oldestFirst = [...hops].reverse();

  // ── Rule 2: Issuer consistency ─────────────────────────────────────────────

  const firstIss = oldestFirst[0]?.iss;
  if (firstIss !== undefined) {
    for (const r of oldestFirst) {
      if (r.iss !== firstIss) {
        hard.push("aar.issuer_inconsistent");
        break;
      }
    }
  }

  // ── Rule 3: Subject consistency ────────────────────────────────────────────

  const firstSubject = oldestFirst[0]?.subject;
  if (firstSubject !== undefined) {
    for (const r of oldestFirst) {
      if (r.subject !== firstSubject) {
        hard.push("aar.subject_inconsistent");
        break;
      }
    }
  }

  // ── Rule 4: At most one revocation ─────────────────────────────────────────

  const revocations = oldestFirst.filter(
    (r) => r.body.event_type === "revocation",
  );
  if (revocations.length > 1) {
    hard.push("aar.multiple_revocations");
  }

  // ── Rule 5: Revocation must reference an issuance ──────────────────────────

  for (const r of revocations) {
    if (r.prev === null) continue; // already caught by chain_head_not_issuance

    const referenced = index.byId.get(r.prev);
    if (referenced !== undefined && referenced.body.event_type !== "issuance") {
      hard.push("aar.revocation_references_non_issuance");
      break;
    }
  }

  return {
    ok: hard.length === 0,
    hard_invalid_reasons: hard,
    warnings: warn,
  };
}
