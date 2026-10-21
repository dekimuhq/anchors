/**
 * ATokR chain walker (spec §6.1 + §6.2).
 *
 * Two concerns that no other anchors family member has:
 *   1. Per-token linear `prev` chain (shared with ABR/AIR but simpler).
 *   2. Rotation tree — `token.rotated` events close one token_id chain and
 *      open another via `rotation_of`. The walker validates both the linear
 *      chain and the cross-chain rotation invariants.
 *
 * 8 validation rules — see walkAtokrChain JSDoc for the full list.
 */

import type {
  AtokrBody,
  AtokrChainReceipt,
  AtokrChainWalkResult,
  AtokrScope,
} from "./types.ts";
import {
  ATOKR_DEFAULT_DEPTH_LIMIT,
  ATOKR_DEPTH_LIMIT_MAX,
  ATOKR_DEPTH_LIMIT_MIN,
} from "./types.ts";

// ── Index ─────────────────────────────────────────────────────────────────────

export interface AtokrChainIndex {
  readonly byId: ReadonlyMap<string, AtokrChainReceipt>;
  readonly byTokenId: ReadonlyMap<string, readonly AtokrChainReceipt[]>;
}

/**
 * Build a lookup index grouping receipts by envelope `id` and by
 * `body.token_id`. Duplicate envelope IDs keep first occurrence.
 */
export function buildAtokrChainIndex(
  receipts: readonly AtokrChainReceipt[],
): AtokrChainIndex {
  const byId = new Map<string, AtokrChainReceipt>();
  const byTokenId = new Map<string, AtokrChainReceipt[]>();

  for (const r of receipts) {
    if (!byId.has(r.id)) byId.set(r.id, r);

    const tid = r.body.token_id;
    const arr = byTokenId.get(tid);
    if (arr !== undefined) {
      arr.push(r);
    } else {
      byTokenId.set(tid, [r]);
    }
  }

  return { byId, byTokenId };
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface AtokrChainWalkOptions {
  /** Max hops. Clamped to [ATOKR_DEPTH_LIMIT_MIN, ATOKR_DEPTH_LIMIT_MAX]. */
  depthLimit?: number;
}

function clampDepth(d: number | undefined): number {
  const v = d ?? ATOKR_DEFAULT_DEPTH_LIMIT;
  if (v < ATOKR_DEPTH_LIMIT_MIN) return ATOKR_DEPTH_LIMIT_MIN;
  if (v > ATOKR_DEPTH_LIMIT_MAX) return ATOKR_DEPTH_LIMIT_MAX;
  return v;
}

// ── Scope helpers ─────────────────────────────────────────────────────────────

/** All 5 scope fields must be strictly equal. */
export function scopesEqual(a: AtokrScope, b: AtokrScope): boolean {
  return (
    a.audience === b.audience &&
    a.purpose === b.purpose &&
    a.valid_from === b.valid_from &&
    a.valid_until === b.valid_until &&
    a.single_use === b.single_use
  );
}

/**
 * True when `rotated` is equal to or narrower than `issuance`.
 *
 * - audience and purpose must match exactly.
 * - valid_from may move forward (or stay equal).
 * - valid_until may move backward (or stay equal); issuance null → rotated
 *   non-null is narrowing (OK); issuance non-null → rotated null is widening.
 * - single_use may go false→true (narrowing) but NOT true→false (widening).
 */
export function isScopeNarrowedOrEqual(
  issuance: AtokrScope,
  rotated: AtokrScope,
): boolean {
  if (issuance.audience !== rotated.audience) return false;
  if (issuance.purpose !== rotated.purpose) return false;

  // valid_from: rotated may be >= issuance (forward or equal)
  if (rotated.valid_from < issuance.valid_from) return false;

  // valid_until: rotated may be <= issuance (backward or equal)
  if (issuance.valid_until === null) {
    // issuance unbounded — rotated non-null = narrowing (OK), null = equal (OK)
  } else if (rotated.valid_until === null) {
    // issuance bounded but rotated unbounded → widening
    return false;
  } else if (rotated.valid_until > issuance.valid_until) {
    return false;
  }

  // single_use: false→true = narrowing (OK); true→false = widening
  if (issuance.single_use && !rotated.single_use) return false;

  return true;
}

// ── Token-id chain helpers ────────────────────────────────────────────────────

/** Find the token.issued receipt in a token_id chain. */
export function findIssuance(
  tokenId: string,
  index: AtokrChainIndex,
): AtokrChainReceipt | undefined {
  const chain = index.byTokenId.get(tokenId);
  if (chain === undefined) return undefined;
  return chain.find((r) => r.body.event_type === "token.issued");
}

/** Check if a token_id chain contains a token.revoked event. */
export function isRevoked(tokenId: string, index: AtokrChainIndex): boolean {
  const chain = index.byTokenId.get(tokenId);
  if (chain === undefined) return false;
  return chain.some((r) => r.body.event_type === "token.revoked");
}

/** Count token.redeemed events in a token_id chain. */
export function countRedeemed(
  tokenId: string,
  index: AtokrChainIndex,
): number {
  const chain = index.byTokenId.get(tokenId);
  if (chain === undefined) return 0;
  return chain.filter((r) => r.body.event_type === "token.redeemed").length;
}

// ── Walker ────────────────────────────────────────────────────────────────────

/**
 * Walk from `startId` backward through `prev`, validating the 8 ATokR chain
 * rules:
 *
 *  1. Prev chain integrity (§6.1) — cycles, dangling, non-issuance head
 *  2. Issuer consistency (§6.2 rule 2)
 *  3. Subject consistency (§6.2 rule 3)
 *  4. Scope consistency (§6.2 rule 4) — exact match for redeemed/revoked,
 *     narrowed-or-equal for rotated
 *  5. Format-class consistency (§6.2 rule 5)
 *  6. Rotation-after-revocation (§6.2 rule 6) + rotation_chain_broken
 *  7. Single-use enforcement (§4.2)
 *  8. Post-revocation events
 */
export function walkAtokrChain(
  startId: string,
  index: AtokrChainIndex,
  opts?: AtokrChainWalkOptions,
): AtokrChainWalkResult {
  const limit = clampDepth(opts?.depthLimit);
  const hard: string[] = [];
  const warn: string[] = [];

  const start = index.byId.get(startId);
  if (start === undefined) {
    return { ok: false, hard_invalid_reasons: ["atokr.receipt_not_found"], warnings: [] };
  }

  // ── Rule 1: Walk prev chain ────────────────────────────────────────────────

  const hops: AtokrChainReceipt[] = [];
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
      // treat as dangling — exceeded depth without reaching head
      dangling = true;
      break;
    }

    cursor = r.prev;
  }

  if (cycle) {
    hard.push("atokr.chain_cycle_detected");
  }
  if (dangling) {
    hard.push("atokr.chain_prev_unresolved");
  }

  // Check non-issuance with prev=null (chain head that is not an issuance)
  const head = hops[hops.length - 1];
  if (
    head !== undefined &&
    !cycle &&
    !dangling &&
    head.prev === null &&
    head.body.event_type !== "token.issued"
  ) {
    hard.push("atokr.chain_prev_unresolved");
  }

  // If the walk had structural failures, bail early — cross-event rules
  // need a clean chain.
  if (hard.length > 0) {
    return { ok: false, hard_invalid_reasons: hard, warnings: warn };
  }

  // Oldest → newest for cross-event rules.
  const oldestFirst = [...hops].reverse();

  // ── Rule 2: Issuer consistency ─────────────────────────────────────────────

  const firstIss = oldestFirst[0]?.iss;
  if (firstIss !== undefined) {
    for (const r of oldestFirst) {
      if (r.iss !== firstIss) {
        hard.push("atokr.issuer_inconsistent");
        break;
      }
    }
  }

  // ── Rule 3: Subject consistency ────────────────────────────────────────────

  const firstSubject = oldestFirst[0]?.subject;
  if (firstSubject !== undefined) {
    for (const r of oldestFirst) {
      if (r.subject !== firstSubject) {
        hard.push("atokr.subject_inconsistent");
        break;
      }
    }
  }

  // For rules 4–8, find the issuance receipt for each relevant token_id.
  // The start receipt's token_id is the primary chain.
  const startTokenId = start.body.token_id;
  const issuanceReceipt = findIssuance(startTokenId, index);

  // ── Rule 4: Scope consistency ──────────────────────────────────────────────

  // For redeemed/revoked in the same token_id: scope must exactly match issuance.
  if (issuanceReceipt !== undefined) {
    const issuanceScope = issuanceReceipt.body.scope;

    for (const r of oldestFirst) {
      if (r.body.event_type === "token.issued") continue;
      if (r.body.token_id !== startTokenId) continue;
      if (
        r.body.event_type === "token.redeemed" ||
        r.body.event_type === "token.revoked"
      ) {
        if (!scopesEqual(issuanceScope, r.body.scope)) {
          hard.push("atokr.scope_mismatch");
          break;
        }
        // scope_expired: iat of redeemed/revoked > issuance scope.valid_until
        if (issuanceScope.valid_until !== null) {
          const iatMs = Date.parse(r.iat);
          const untilMs = Date.parse(issuanceScope.valid_until);
          if (!Number.isNaN(iatMs) && !Number.isNaN(untilMs) && iatMs > untilMs) {
            hard.push("atokr.scope_expired");
          }
        }
      }
    }
  }

  // For rotated events: scope must be narrowed-or-equal vs the rotation_of issuance.
  for (const r of oldestFirst) {
    if (r.body.event_type !== "token.rotated") continue;
    const rotatedFromId = r.body.rotation_of;
    const rotatedFromIssuance = findIssuance(rotatedFromId, index);
    if (rotatedFromIssuance !== undefined) {
      if (!isScopeNarrowedOrEqual(rotatedFromIssuance.body.scope, r.body.scope)) {
        hard.push("atokr.scope_widened");
        break;
      }
    }
  }

  // ── Rule 5: Format-class consistency ───────────────────────────────────────

  if (issuanceReceipt !== undefined) {
    const issuanceFc = issuanceReceipt.body.format_class;
    for (const r of oldestFirst) {
      if (r.body.event_type === "token.issued") continue;
      if (r.body.token_id !== startTokenId) continue;
      if (r.body.format_class !== null && r.body.format_class !== issuanceFc) {
        hard.push("atokr.format_class_mismatch");
        break;
      }
    }
  }

  // ── Rule 6: Rotation-after-revocation ──────────────────────────────────────

  for (const r of oldestFirst) {
    if (r.body.event_type !== "token.rotated") continue;
    const rotatedFromId = r.body.rotation_of;

    // Check if rotation_of references an unknown token_id
    const rotatedFromChain = index.byTokenId.get(rotatedFromId);
    if (rotatedFromChain === undefined || rotatedFromChain.length === 0) {
      hard.push("atokr.rotation_chain_broken");
      break;
    }

    // Check if the source chain contains a revoked event
    if (isRevoked(rotatedFromId, index)) {
      hard.push("atokr.rotation_after_revocation");
      break;
    }
  }

  // ── Rule 7: Single-use enforcement ─────────────────────────────────────────

  if (issuanceReceipt !== undefined && issuanceReceipt.body.scope.single_use) {
    const redeemCount = countRedeemed(startTokenId, index);
    if (redeemCount > 1) {
      hard.push("atokr.single_use_exhausted");
    }
  }

  // ── Rule 8: Post-revocation events ─────────────────────────────────────────

  if (isRevoked(startTokenId, index)) {
    // Sort token_id chain by iat to determine temporal order.
    const chain = index.byTokenId.get(startTokenId);
    if (chain !== undefined) {
      const sorted = [...chain].sort(
        (a, b) => Date.parse(a.iat) - Date.parse(b.iat),
      );
      let revokedSeen = false;
      for (const r of sorted) {
        if (r.body.event_type === "token.revoked") {
          revokedSeen = true;
        } else if (revokedSeen && r.body.event_type === "token.redeemed") {
          hard.push("atokr.token_revoked_prior");
          break;
        }
      }
    }
  }

  return {
    ok: hard.length === 0,
    hard_invalid_reasons: hard,
    warnings: warn,
  };
}
