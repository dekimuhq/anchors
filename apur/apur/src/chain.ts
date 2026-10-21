/**
 * APuR chain walker (spec §7.1 + §7.2).
 *
 * Validates the linear lifecycle chain:
 *   binding (head, prev=null) → repurpose* → unbinding (terminal)
 *
 * 5 validation rules:
 *  1. Prev chain integrity — no cycles, no dangling refs, depth limit
 *  2. Head must be binding — chain root must have event_type "binding"
 *  3. Issuer consistency — all events share same `iss`
 *  4. Terminal enforcement — no events after unbinding
 *  5. Event ordering — binding first, only repurpose between, unbinding last
 *
 * 1 warning:
 *  - aborted_retest_still_open — repurpose with incompatible_aborted but no unbinding
 */

import type {
  ApurBody,
  ApurChainReceipt,
  ApurChainWalkResult,
} from "./types.ts";
import {
  APUR_DEFAULT_DEPTH_LIMIT,
  APUR_DEPTH_LIMIT_MAX,
  APUR_DEPTH_LIMIT_MIN,
} from "./types.ts";

// Suppress unused import warning — ApurBody is used via the receipt type
const _: ApurBody | undefined = undefined;
void _;

// ── Index ─────────────────────────────────────────────────────────────────────

export interface ApurChainIndex {
  readonly byId: ReadonlyMap<string, ApurChainReceipt>;
}

/**
 * Build a lookup index by envelope `id`.
 * Duplicate IDs keep first occurrence.
 */
export function buildApurChainIndex(
  receipts: readonly ApurChainReceipt[],
): ApurChainIndex {
  const byId = new Map<string, ApurChainReceipt>();
  for (const r of receipts) {
    if (!byId.has(r.id)) byId.set(r.id, r);
  }
  return { byId };
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface ApurChainWalkOptions {
  /** Max hops. Clamped to [APUR_DEPTH_LIMIT_MIN, APUR_DEPTH_LIMIT_MAX]. */
  depthLimit?: number;
}

function clampDepth(d: number | undefined): number {
  const v = d ?? APUR_DEFAULT_DEPTH_LIMIT;
  if (v < APUR_DEPTH_LIMIT_MIN) return APUR_DEPTH_LIMIT_MIN;
  if (v > APUR_DEPTH_LIMIT_MAX) return APUR_DEPTH_LIMIT_MAX;
  return v;
}

// ── Walker ────────────────────────────────────────────────────────────────────

/**
 * Walk from `startId` backward through `prev`, validating the 5 APuR chain
 * rules.
 *
 * Error codes (hard_invalid_reasons):
 *  - apur.receipt_not_found
 *  - apur.chain_cycle_detected
 *  - apur.chain_prev_unresolved
 *  - apur.chain_head_not_binding
 *  - apur.issuer_inconsistent
 *  - apur.event_after_unbinding
 *  - apur.duplicate_binding
 *  - apur.repurpose_before_binding
 *  - apur.unbinding_before_binding
 *
 * Warning codes:
 *  - apur.aborted_retest_still_open
 */
export function walkApurChain(
  startId: string,
  index: ApurChainIndex,
  opts?: ApurChainWalkOptions,
): ApurChainWalkResult {
  const limit = clampDepth(opts?.depthLimit);
  const hard: string[] = [];
  const warn: string[] = [];

  const start = index.byId.get(startId);
  if (start === undefined) {
    return { ok: false, hard_invalid_reasons: ["apur.receipt_not_found"], warnings: [] };
  }

  // ── Rule 1: Walk prev chain ────────────────────────────────────────────────

  const hops: ApurChainReceipt[] = [];
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
      // Exceeded depth without reaching head — treat as dangling
      dangling = true;
      break;
    }

    cursor = r.prev;
  }

  if (cycle) hard.push("apur.chain_cycle_detected");
  if (dangling) hard.push("apur.chain_prev_unresolved");

  // Bail early if chain is structurally broken
  if (hard.length > 0) {
    return { ok: false, hard_invalid_reasons: hard, warnings: warn };
  }

  // Oldest → newest for ordering rules
  const oldestFirst = [...hops].reverse();

  // ── Rule 2: Head must be binding ───────────────────────────────────────────

  const head = oldestFirst[0];
  if (head !== undefined && head.body.event_type !== "binding") {
    hard.push("apur.chain_head_not_binding");
    return { ok: false, hard_invalid_reasons: hard, warnings: warn };
  }

  // ── Rule 3: Issuer consistency ─────────────────────────────────────────────

  const firstIss = oldestFirst[0]?.iss;
  if (firstIss !== undefined) {
    for (const r of oldestFirst) {
      if (r.iss !== firstIss) {
        hard.push("apur.issuer_inconsistent");
        break;
      }
    }
  }

  // ── Rules 4 + 5: Event ordering + terminal enforcement ────────────────────

  let bindingCount = 0;
  let unbindingSeen = false;
  let unbindingIndex = -1;

  for (let i = 0; i < oldestFirst.length; i++) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const r = oldestFirst[i]!;
    const et = r.body.event_type;

    if (et === "binding") {
      bindingCount++;
      if (bindingCount > 1) {
        hard.push("apur.duplicate_binding");
      }
      if (unbindingSeen) {
        hard.push("apur.event_after_unbinding");
      }
    } else if (et === "repurpose") {
      if (bindingCount === 0) {
        hard.push("apur.repurpose_before_binding");
      }
      if (unbindingSeen) {
        hard.push("apur.event_after_unbinding");
      }
    } else if (et === "unbinding") {
      if (bindingCount === 0) {
        hard.push("apur.unbinding_before_binding");
      }
      if (!unbindingSeen) {
        unbindingSeen = true;
        unbindingIndex = i;
      } else {
        // Second unbinding — also event_after_unbinding
        hard.push("apur.event_after_unbinding");
      }
    }
  }

  // Suppress unused variable warning
  void unbindingIndex;

  // ── Warning: aborted_retest_still_open ────────────────────────────────────

  if (hard.length === 0) {
    const hasAborted = oldestFirst.some(
      (r) =>
        r.body.event_type === "repurpose" &&
        r.body.compat_conclusion === "incompatible_aborted",
    );

    if (hasAborted && !unbindingSeen) {
      warn.push("apur.aborted_retest_still_open");
    }
  }

  return {
    ok: hard.length === 0,
    hard_invalid_reasons: hard,
    warnings: warn,
  };
}
