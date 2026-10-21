/**
 * ADR chain walker + state machine (spec §7.1).
 *
 * Walks a linear `prev` chain from the newest receipt back to the root grant,
 * then replays events oldest-to-newest computing:
 *   - Current authority state (Active / Suspended / Revoked / Expired)
 *   - Effective scope (after narrows)
 *   - Chain summary (root id, depth, last event)
 *
 * State machine transitions (§7.1):
 *   grant    → Active  (root, prev=null)
 *   narrow   → Active  (from Active only)
 *   renew    → (unchanged state) (from Active or Suspended)
 *   suspend  → Suspended (from Active only)
 *   resume   → Active  (from Suspended only)
 *   revoke   → Revoked (terminal) (from Active or Suspended)
 *
 * Expiry: if effective expiry < clock, state = Expired (terminal).
 */

import type {
  AdrBody,
  AdrChainReceipt,
  AdrChainSummary,
  AdrChainWalkResult,
  AdrScope,
  AdrState,
} from "./types.ts";
import {
  ADR_CHAIN_DEPTH_LIMIT_MAX,
  ADR_CHAIN_DEPTH_LIMIT_MIN,
  ADR_DEFAULT_CHAIN_DEPTH_LIMIT,
} from "./types.ts";
import { isScopeSubset } from "./scope.ts";

// ── Index ─────────────────────────────────────────────────────────────────────

export interface AdrChainIndex {
  readonly byId: ReadonlyMap<string, AdrChainReceipt>;
}

/**
 * Build a lookup index from a flat array of receipts.
 * Duplicate envelope IDs keep first occurrence.
 */
export function buildAdrChainIndex(
  receipts: readonly AdrChainReceipt[],
): AdrChainIndex {
  const byId = new Map<string, AdrChainReceipt>();
  for (const r of receipts) {
    if (!byId.has(r.id)) byId.set(r.id, r);
  }
  return { byId };
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface AdrChainWalkOptions {
  /** Max hops. Clamped to [ADR_CHAIN_DEPTH_LIMIT_MIN, ADR_CHAIN_DEPTH_LIMIT_MAX]. */
  depthLimit?: number;
  /** Unix seconds. Used for expiry comparison. Defaults to now. */
  clock?: number;
}

function clampDepth(d: number | undefined): number {
  const v = d ?? ADR_DEFAULT_CHAIN_DEPTH_LIMIT;
  if (v < ADR_CHAIN_DEPTH_LIMIT_MIN) return ADR_CHAIN_DEPTH_LIMIT_MIN;
  if (v > ADR_CHAIN_DEPTH_LIMIT_MAX) return ADR_CHAIN_DEPTH_LIMIT_MAX;
  return v;
}

// ── Valid transitions ─────────────────────────────────────────────────────────

const VALID_TRANSITIONS: Record<string, readonly AdrState[]> = {
  narrow:  ["Active"],
  renew:   ["Active", "Suspended"],
  suspend: ["Active"],
  resume:  ["Suspended"],
  revoke:  ["Active", "Suspended"],
};

const TERMINAL_STATES: ReadonlySet<AdrState> = new Set(["Revoked", "Expired"]);

// ── Helpers ───────────────────────────────────────────────────────────────────

function fail(reasons: string[], warnings?: string[]): AdrChainWalkResult {
  return {
    ok: false,
    state: "Revoked",
    effective_scope: null,
    hard_invalid_reasons: reasons,
    warnings: warnings ?? [],
    chain_summary: null,
  };
}

// ── Walker ────────────────────────────────────────────────────────────────────

/**
 * Walk from `startId` backward through `prev`, then replay events
 * oldest-to-newest through the ADR state machine.
 *
 * Validation rules:
 *  1. Prev chain integrity — cycles, dangling refs, depth exceeded
 *  2. Chain head must be a grant with prev=null
 *  3. Issuer consistency (all same iss)
 *  4. Subject consistency (all same subject)
 *  5. State machine transitions (§7.1)
 *  6. Narrow scope-subset validation via isScopeSubset
 *  7. Renew expiry warning (new expiry not greater than current)
 *  8. Expiry vs clock at end
 */
export function walkAdrChain(
  startId: string,
  index: AdrChainIndex,
  opts?: AdrChainWalkOptions,
): AdrChainWalkResult {
  const limit = clampDepth(opts?.depthLimit);
  const clock = opts?.clock ?? Math.floor(Date.now() / 1000);
  const hard: string[] = [];
  const warn: string[] = [];

  // ── Step 0: Resolve start ───────────────────────────────────────────────

  const start = index.byId.get(startId);
  if (start === undefined) {
    return fail(["adr.receipt_not_found"]);
  }

  // ── Step 1: Walk prev chain newest → oldest ─────────────────────────────

  const hops: AdrChainReceipt[] = [];
  const visited = new Set<string>();
  let cursor: string | null = startId;

  while (cursor !== null) {
    if (visited.has(cursor)) {
      return fail(["adr.chain_cycle_detected"]);
    }
    visited.add(cursor);

    const r = index.byId.get(cursor);
    if (r === undefined) {
      return fail(["adr.chain_prev_unresolved"]);
    }

    hops.push(r);

    if (hops.length > limit) {
      return fail(["adr.chain_depth_exceeded"]);
    }

    cursor = r.prev;
  }

  // ── Step 2: Head must be a grant with prev=null ─────────────────────────

  const head = hops[hops.length - 1];
  if (head === undefined || head.body.event !== "grant" || head.prev !== null) {
    return fail(["adr.chain_head_not_grant"]);
  }

  // Oldest → newest for state replay.
  const oldestFirst = [...hops].reverse();

  // ── Step 3: Issuer consistency ──────────────────────────────────────────

  const rootIss = head.iss;
  for (const r of oldestFirst) {
    if (r.iss !== rootIss) {
      hard.push("adr.issuer_inconsistent");
      break;
    }
  }

  // ── Step 4: Subject consistency ─────────────────────────────────────────

  const rootSubject = head.subject;
  for (const r of oldestFirst) {
    if (r.subject !== rootSubject) {
      hard.push("adr.subject_inconsistent");
      break;
    }
  }

  // Bail early on structural issues before state machine.
  if (hard.length > 0) {
    return {
      ok: false,
      state: "Revoked",
      effective_scope: null,
      hard_invalid_reasons: hard,
      warnings: warn,
      chain_summary: null,
    };
  }

  // ── Step 5–7: State machine replay ──────────────────────────────────────

  let state: AdrState = "Active"; // grant sets initial state
  const grantBody = head.body as { scope: AdrScope; expiry: number | null };
  let effectiveScope: AdrScope = grantBody.scope;
  let effectiveExpiry: number | null = grantBody.expiry;

  // Process events oldest → newest (skip the grant itself).
  for (let i = 1; i < oldestFirst.length; i++) {
    const receipt = oldestFirst[i]!;
    const body: AdrBody = receipt.body;
    const event = body.event;

    // Check terminal state — no further events allowed.
    if (TERMINAL_STATES.has(state)) {
      hard.push("adr.chain_terminal");
      break;
    }

    // Check valid transition.
    const allowed = VALID_TRANSITIONS[event];
    if (allowed === undefined || !allowed.includes(state)) {
      hard.push("adr.state_machine_invalid");
      break;
    }

    switch (event) {
      case "narrow": {
        const narrowBody = body as { scope: AdrScope };
        const subsetResult = isScopeSubset(narrowBody.scope, effectiveScope);
        if (!subsetResult.ok) {
          hard.push("adr.scope_widening");
          break;
        }
        effectiveScope = narrowBody.scope;
        // state remains Active
        break;
      }

      case "renew": {
        const renewBody = body as { expiry: number };
        if (
          effectiveExpiry !== null &&
          renewBody.expiry <= effectiveExpiry
        ) {
          warn.push("adr.renew_expiry_not_extended");
        }
        effectiveExpiry = renewBody.expiry;
        // state unchanged
        break;
      }

      case "suspend":
        state = "Suspended";
        break;

      case "resume":
        state = "Active";
        break;

      case "revoke":
        state = "Revoked";
        break;
    }

    // Stop processing if a hard error was added (e.g. scope_widening).
    if (hard.length > 0) break;
  }

  // ── Step 8: Expiry check ────────────────────────────────────────────────

  if (
    hard.length === 0 &&
    !TERMINAL_STATES.has(state) &&
    effectiveExpiry !== null &&
    effectiveExpiry < clock
  ) {
    state = "Expired";
  }

  // ── Build summary ───────────────────────────────────────────────────────

  const lastReceipt = oldestFirst[oldestFirst.length - 1]!;
  const chainSummary: AdrChainSummary = {
    root_id: head.id,
    depth: oldestFirst.length,
    last_event: lastReceipt.body.event,
    last_event_at: lastReceipt.iat,
  };

  return {
    ok: hard.length === 0,
    state,
    effective_scope: hard.length === 0 ? effectiveScope : null,
    hard_invalid_reasons: hard,
    warnings: warn,
    chain_summary: chainSummary,
  };
}
