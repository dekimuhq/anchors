/**
 * ATR chain walker + transfer validity computation (spec §7).
 *
 * Three chain types:
 *   1. Arrangement chain: arrangement (head, prev=null) ← suspension(s) via prev
 *   2. TIA chain: tia (head, prev=null) ← tia (via prev). Latest = current.
 *   3. Transfer events: leaves with no prev, no successors.
 *
 * Core feature: checkTransferValidity — spec §7.2.
 */

import type {
  AtrArrangementBody,
  AtrChainReceipt,
  AtrChainWalkResult,
  AtrSuspensionBody,
  AtrTiaBody,
  AtrTransferBody,
  AtrTransferValidityResult,
} from "./types.ts";
import {
  ATR_DEFAULT_DEPTH_LIMIT,
  ATR_DEPTH_LIMIT_MAX,
  ATR_DEPTH_LIMIT_MIN,
} from "./types.ts";

// ── Profiles that mandate a TIA (spec §7.2 rule 3) ────────────────────────────

const TIA_REQUIRED_PROFILES = new Set<string>([
  "gdpr.art46.scc",
  "gdpr.art46.bcr",
  "gdpr.art46.idta",
  "gdpr.art47.bcr_authorised",
]);

// ── Index ─────────────────────────────────────────────────────────────────────

export interface AtrChainIndex {
  readonly byId: ReadonlyMap<string, AtrChainReceipt>;
  readonly byEventType: ReadonlyMap<string, readonly AtrChainReceipt[]>;
}

/**
 * Build a lookup index grouping receipts by envelope `id` and by
 * `body.event_type`. Duplicate envelope IDs keep first occurrence.
 */
export function buildAtrChainIndex(
  receipts: readonly AtrChainReceipt[],
): AtrChainIndex {
  const byId = new Map<string, AtrChainReceipt>();
  const byEventType = new Map<string, AtrChainReceipt[]>();

  for (const r of receipts) {
    if (!byId.has(r.id)) byId.set(r.id, r);

    const et = r.body.event_type;
    const arr = byEventType.get(et);
    if (arr !== undefined) {
      arr.push(r);
    } else {
      byEventType.set(et, [r]);
    }
  }

  return { byId, byEventType };
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface AtrChainWalkOptions {
  /** Max hops. Clamped to [ATR_DEPTH_LIMIT_MIN, ATR_DEPTH_LIMIT_MAX]. */
  depthLimit?: number;
}

function clampDepth(d: number | undefined): number {
  const v = d ?? ATR_DEFAULT_DEPTH_LIMIT;
  if (v < ATR_DEPTH_LIMIT_MIN) return ATR_DEPTH_LIMIT_MIN;
  if (v > ATR_DEPTH_LIMIT_MAX) return ATR_DEPTH_LIMIT_MAX;
  return v;
}

// ── Arrangement chain walker (spec §7.1) ──────────────────────────────────────

/**
 * Walk `prev` backward from `startId`, validating the arrangement chain.
 * Validates: no cycles, no dangling prev, head must be an arrangement,
 * and issuer consistency across all nodes.
 */
export function walkAtrArrangementChain(
  startId: string,
  index: AtrChainIndex,
  opts?: AtrChainWalkOptions,
): AtrChainWalkResult {
  const limit = clampDepth(opts?.depthLimit);
  const hard: string[] = [];
  const warn: string[] = [];

  const start = index.byId.get(startId);
  if (start === undefined) {
    return {
      ok: false,
      hard_invalid_reasons: ["atr.receipt_not_found"],
      warnings: [],
    };
  }

  // Walk prev chain
  const hops: AtrChainReceipt[] = [];
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
      dangling = true;
      break;
    }

    cursor = r.prev;
  }

  if (cycle) hard.push("atr.chain_cycle_detected");
  if (dangling) hard.push("atr.chain_prev_unresolved");

  if (hard.length > 0) {
    return { ok: false, hard_invalid_reasons: hard, warnings: warn };
  }

  // Head must be an arrangement with prev=null
  const head = hops[hops.length - 1];
  if (head !== undefined && head.body.event_type !== "arrangement") {
    hard.push("atr.chain_head_not_arrangement");
  }

  if (hard.length > 0) {
    return { ok: false, hard_invalid_reasons: hard, warnings: warn };
  }

  // Issuer consistency
  const oldestFirst = [...hops].reverse();
  const firstIss = oldestFirst[0]?.iss;
  if (firstIss !== undefined) {
    for (const r of oldestFirst) {
      if (r.iss !== firstIss) {
        hard.push("atr.issuer_inconsistent");
        break;
      }
    }
  }

  return {
    ok: hard.length === 0,
    hard_invalid_reasons: hard,
    warnings: warn,
  };
}

// ── Suspension finder ─────────────────────────────────────────────────────────

/**
 * Find all suspension receipts whose prev chain leads back to `arrangementId`.
 * Returns the suspension receipts themselves (not the full chains).
 */
function findSuspensionsForArrangement(
  arrangementId: string,
  index: AtrChainIndex,
): AtrChainReceipt[] {
  const suspensions = (index.byEventType.get("suspension") ?? []) as AtrChainReceipt[];
  const result: AtrChainReceipt[] = [];

  for (const susp of suspensions) {
    // Walk susp's prev chain to see if it terminates at arrangementId
    let cursor: string | null = susp.prev;
    const visited = new Set<string>();
    let found = false;

    while (cursor !== null) {
      if (visited.has(cursor)) break; // cycle guard
      visited.add(cursor);

      if (cursor === arrangementId) {
        found = true;
        break;
      }

      const r = index.byId.get(cursor);
      if (r === undefined) break; // dangling
      cursor = r.prev;
    }

    if (found) result.push(susp);
  }

  return result;
}

// ── Hash resolver (v1: hash = receipt ID) ─────────────────────────────────────

function findReceiptByContentHash(
  hash: string,
  index: AtrChainIndex,
): AtrChainReceipt | undefined {
  return index.byId.get(hash);
}

// ── Transfer validity (spec §7.2) ─────────────────────────────────────────────

/**
 * Compute whether a transfer receipt is valid per spec §7.2.
 *
 * Rule 1: arrangement must be in force at transfer_window_start
 * Rule 2: no suspension effective at or before transfer_window_start
 * Rule 3: if profile mandates TIA, tia must be valid at transfer_window_start
 * Rule 4 (warning): transfer window spans a suspension event
 */
export function checkTransferValidity(
  transferId: string,
  index: AtrChainIndex,
): AtrTransferValidityResult {
  const reasons: string[] = [];
  const warnings: string[] = [];

  const receipt = index.byId.get(transferId);
  if (receipt === undefined || receipt.body.event_type !== "transfer") {
    return { valid: false, reasons: ["atr.transfer_not_found"] };
  }

  const transfer = receipt.body as AtrTransferBody;
  const windowStart = transfer.transfer_window_start;
  const windowEnd = transfer.transfer_window_end;
  const windowStartMs = Date.parse(windowStart);
  const windowEndMs = Date.parse(windowEnd);

  // ── Rule 1: Arrangement must exist and be in force ────────────────────────

  const arrangementReceipt = findReceiptByContentHash(
    transfer.arrangement_hash,
    index,
  );

  if (
    arrangementReceipt === undefined ||
    arrangementReceipt.body.event_type !== "arrangement"
  ) {
    reasons.push("atr.arrangement_not_found");
    return { valid: false, reasons };
  }

  const arrangement = arrangementReceipt.body as AtrArrangementBody;
  const inForceFromMs = Date.parse(arrangement.in_force_from);

  if (!Number.isNaN(inForceFromMs) && inForceFromMs > windowStartMs) {
    reasons.push("atr.arrangement_not_in_force");
  }

  if (arrangement.in_force_until !== null) {
    const inForceUntilMs = Date.parse(arrangement.in_force_until);
    if (!Number.isNaN(inForceUntilMs) && inForceUntilMs <= windowStartMs) {
      reasons.push("atr.arrangement_expired");
    }
  }

  // ── Rule 2: No suspension effective at or before transfer_window_start ────

  const suspensions = findSuspensionsForArrangement(
    arrangementReceipt.id,
    index,
  );

  for (const susp of suspensions) {
    const suspBody = susp.body as AtrSuspensionBody;
    const effectiveAtMs = Date.parse(suspBody.effective_at);

    if (!Number.isNaN(effectiveAtMs) && effectiveAtMs <= windowStartMs) {
      reasons.push("atr.arrangement_suspended");
      break;
    }
  }

  // ── Rule 4 (warning): transfer window spans a suspension ─────────────────

  for (const susp of suspensions) {
    const suspBody = susp.body as AtrSuspensionBody;
    const effectiveAtMs = Date.parse(suspBody.effective_at);

    if (
      !Number.isNaN(effectiveAtMs) &&
      effectiveAtMs > windowStartMs &&
      effectiveAtMs <= windowEndMs
    ) {
      warnings.push("atr.transfer_spans_suspension");
      break;
    }
  }

  // ── Rule 3: TIA check ─────────────────────────────────────────────────────

  const profileRequiresTia = TIA_REQUIRED_PROFILES.has(receipt.profile);

  if (profileRequiresTia) {
    if (transfer.tia_hash === null) {
      reasons.push("atr.tia_required");
    } else {
      const tiaReceipt = findReceiptByContentHash(transfer.tia_hash, index);

      if (tiaReceipt === undefined || tiaReceipt.body.event_type !== "tia") {
        reasons.push("atr.tia_not_found");
      } else {
        const tia = tiaReceipt.body as AtrTiaBody;
        const tiaValidFromMs = Date.parse(tia.valid_from);
        const tiaValidUntilMs = Date.parse(tia.valid_until);

        if (
          Number.isNaN(tiaValidFromMs) ||
          Number.isNaN(tiaValidUntilMs) ||
          tiaValidFromMs > windowStartMs ||
          tiaValidUntilMs <= windowStartMs
        ) {
          reasons.push("atr.tia_expired");
        }
      }
    }
  }

  const allReasons = [...reasons, ...warnings];
  const hardFail = reasons.length > 0;

  return {
    valid: !hardFail,
    reasons: allReasons,
  };
}
