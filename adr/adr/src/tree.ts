/**
 * ADR delegation tree walker (spec §7.2).
 *
 * Handles sub-delegation: a child grant's `prev` points at its parent grant,
 * forming a tree of authority chains. This is DISTINCT from the linear chain
 * walker (which handles lifecycle events on a single chain).
 *
 * Tree walk evaluates:
 *   1. Walk `prev` pointers on grants to find the root of the delegation tree
 *   2. At each ancestor verify:
 *      - Parent `delegable === true`
 *      - Child scope ⊆ parent effective scope
 *      - Child expiry ≤ parent expiry
 *      - Child `delegable` not exceeding parent `delegable`
 *   3. Cascade state:
 *      - Ancestor Revoked → this receipt effectively Revoked
 *      - Ancestor Suspended → effectively Suspended
 *      - Ancestor Expired → effectively Expired
 *      - Revoked/Expired take precedence over Suspended
 */

import type {
  AdrChainReceipt,
  AdrGrantBody,
  AdrScope,
  AdrState,
  AdrTreeIndex,
  AdrTreeWalkResult,
} from "./types.ts";
import {
  ADR_DEFAULT_TREE_DEPTH_LIMIT,
  ADR_TREE_DEPTH_LIMIT_MAX,
  ADR_TREE_DEPTH_LIMIT_MIN,
} from "./types.ts";
import type { AdrChainIndex } from "./chain.ts";
import { walkAdrChain } from "./chain.ts";
import { isScopeSubset } from "./scope.ts";

// ── Options ──────────────────────────────────────────────────────────────────

export interface AdrTreeWalkOptions {
  /** Max tree depth (ancestor hops). Clamped to [TREE_MIN, TREE_MAX]. */
  treeDepthLimit?: number;
  /** Max chain depth passed through to walkAdrChain. */
  chainDepthLimit?: number;
  /** Unix seconds. Used for expiry comparison. Defaults to now. */
  clock?: number;
}

function clampTreeDepth(d: number | undefined): number {
  const v = d ?? ADR_DEFAULT_TREE_DEPTH_LIMIT;
  if (v < ADR_TREE_DEPTH_LIMIT_MIN) return ADR_TREE_DEPTH_LIMIT_MIN;
  if (v > ADR_TREE_DEPTH_LIMIT_MAX) return ADR_TREE_DEPTH_LIMIT_MAX;
  return v;
}

// ── Tree index ───────────────────────────────────────────────────────────────

/**
 * Build a tree index from a flat array of receipts.
 *
 * `byId` maps receipt ID → receipt. `childrenOf` maps a grant receipt ID →
 * IDs of grants whose `prev` points at it (sub-delegations).
 */
export function buildAdrTreeIndex(
  receipts: readonly AdrChainReceipt[],
): AdrTreeIndex {
  const byId = new Map<string, AdrChainReceipt>();
  const childrenOf = new Map<string, string[]>();

  for (const r of receipts) {
    if (!byId.has(r.id)) byId.set(r.id, r);
  }

  // Only grant-to-grant prev links form tree edges.
  for (const r of receipts) {
    if (r.body.event === "grant" && r.prev !== null) {
      const parent = byId.get(r.prev);
      if (parent !== undefined && parent.body.event === "grant") {
        const siblings = childrenOf.get(r.prev);
        if (siblings !== undefined) {
          siblings.push(r.id);
        } else {
          childrenOf.set(r.prev, [r.id]);
        }
      }
    }
  }

  return { byId, childrenOf };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function fail(reasons: string[]): AdrTreeWalkResult {
  return {
    ok: false,
    effective_state: "Revoked",
    effective_scope: null,
    hard_invalid_reasons: reasons,
    warnings: [],
    ancestor_depth: 0,
  };
}

/**
 * Result of building an isolated chain for a single grant.
 */
interface IsolatedChain {
  readonly index: AdrChainIndex;
  /** The tip (newest) receipt ID in the chain — start walkAdrChain here. */
  readonly tipId: string;
}

/**
 * Build an isolated chain index for a single grant node.
 *
 * The grant's `prev` is overridden to `null` so the chain walker treats it as
 * a chain root. Only lifecycle events (non-grant) whose `prev` chain resolves
 * back to this grant are included.
 *
 * Returns the index plus the tip ID (the receipt with no children in the chain)
 * since `walkAdrChain` must start from the newest event, not the root.
 */
function buildIsolatedChain(
  grantId: string,
  allReceipts: ReadonlyMap<string, AdrChainReceipt>,
): IsolatedChain {
  const grant = allReceipts.get(grantId);
  if (grant === undefined) {
    return { index: { byId: new Map() }, tipId: grantId };
  }

  const byId = new Map<string, AdrChainReceipt>();

  // Insert the grant as a root (prev=null).
  byId.set(grantId, { ...grant, prev: null });

  // Collect all non-grant events that eventually chain back to this grant.
  // Walk all receipts whose prev chain resolves to grantId without crossing
  // another grant.
  for (const [id, r] of allReceipts) {
    if (id === grantId) continue;
    if (r.body.event === "grant") continue;

    // Walk prev from this event back, checking if it reaches grantId.
    let cursor: string | null = r.prev;
    const path: AdrChainReceipt[] = [r];
    let reachesGrant = false;

    while (cursor !== null) {
      if (cursor === grantId) {
        reachesGrant = true;
        break;
      }
      const next = allReceipts.get(cursor);
      if (next === undefined || next.body.event === "grant") break;
      path.push(next);
      cursor = next.prev;
    }

    if (reachesGrant) {
      for (const p of path) {
        if (!byId.has(p.id)) byId.set(p.id, p);
      }
    }
  }

  // Find the tip: the receipt in the chain that no other receipt points to.
  const pointed = new Set<string>();
  for (const [, r] of byId) {
    if (r.prev !== null) pointed.add(r.prev);
  }
  let tipId = grantId;
  for (const [id] of byId) {
    if (!pointed.has(id)) {
      tipId = id;
      break;
    }
  }

  return { index: { byId }, tipId };
}

// ── Tree walker ──────────────────────────────────────────────────────────────

/**
 * Walk the delegation tree for `receiptId`, validating sub-delegation rules
 * and computing cascade state from ancestors.
 *
 * For root grants (prev=null), delegates directly to `walkAdrChain`.
 */
export function walkDelegationTree(
  receiptId: string,
  treeIndex: AdrTreeIndex,
  chainIndex: AdrChainIndex,
  opts?: AdrTreeWalkOptions,
): AdrTreeWalkResult {
  const treeLimit = clampTreeDepth(opts?.treeDepthLimit);
  const clock = opts?.clock ?? Math.floor(Date.now() / 1000);

  // ── Resolve receipt ────────────────────────────────────────────────────

  const receipt = treeIndex.byId.get(receiptId);
  if (receipt === undefined) {
    return fail(["adr.receipt_not_found"]);
  }

  if (receipt.body.event !== "grant") {
    return fail(["adr.tree_node_not_grant"]);
  }

  const grantBody = receipt.body as AdrGrantBody;

  // ── Root grant shortcut ────────────────────────────────────────────────

  if (receipt.prev === null) {
    const chainResult = walkAdrChain(receiptId, chainIndex, {
      ...(opts?.chainDepthLimit !== undefined && { depthLimit: opts.chainDepthLimit }),
      clock,
    });
    return {
      ok: chainResult.ok,
      effective_state: chainResult.state,
      effective_scope: chainResult.effective_scope,
      hard_invalid_reasons: [...chainResult.hard_invalid_reasons],
      warnings: [...chainResult.warnings],
      ancestor_depth: 0,
    };
  }

  // ── Walk ancestors (child → root) ──────────────────────────────────────

  const ancestors: Array<{
    receipt: AdrChainReceipt;
    grantBody: AdrGrantBody;
  }> = [];
  const visited = new Set<string>();
  let cursor: string | null = receipt.prev;

  while (cursor !== null) {
    if (visited.has(cursor)) {
      return fail(["adr.tree_cycle_detected"]);
    }
    visited.add(cursor);

    const parent = treeIndex.byId.get(cursor);
    if (parent === undefined) {
      return fail(["adr.tree_parent_unresolved"]);
    }
    if (parent.body.event !== "grant") {
      return fail(["adr.tree_parent_not_grant"]);
    }

    ancestors.push({
      receipt: parent,
      grantBody: parent.body as AdrGrantBody,
    });

    if (ancestors.length > treeLimit) {
      return fail(["adr.tree_depth_exceeded"]);
    }

    cursor = parent.prev;
  }

  const ancestorDepth = ancestors.length;

  // ── Validate delegation rules at each edge ─────────────────────────────
  // Walk from immediate parent outward. Each child must satisfy constraints
  // relative to its direct parent.

  const hard: string[] = [];
  const warn: string[] = [];

  // Build chain: [this_grant, parent, grandparent, …, root]
  const chain: Array<{ receipt: AdrChainReceipt; grantBody: AdrGrantBody }> = [
    { receipt, grantBody },
    ...ancestors,
  ];

  for (let i = 0; i < chain.length - 1; i++) {
    const child = chain[i]!;
    const parent = chain[i + 1]!;

    // Parent must allow sub-delegation.
    if (!parent.grantBody.delegable) {
      hard.push("adr.delegation_not_permitted");
      break;
    }

    // Child delegable must not exceed parent delegable.
    if (child.grantBody.delegable && !parent.grantBody.delegable) {
      hard.push("adr.delegation_widening");
      break;
    }

    // Child scope ⊆ parent scope.
    const scopeCheck = isScopeSubset(
      child.grantBody.scope,
      parent.grantBody.scope,
    );
    if (!scopeCheck.ok) {
      hard.push("adr.delegation_scope_exceeded");
      break;
    }

    // Child expiry ≤ parent expiry.
    if (
      parent.grantBody.expiry !== null &&
      child.grantBody.expiry !== null &&
      child.grantBody.expiry > parent.grantBody.expiry
    ) {
      hard.push("adr.delegation_expiry_exceeded");
      break;
    }
    // parent null expiry = no limit, always OK.
    // child null expiry but parent has expiry = child outlives parent.
    if (child.grantBody.expiry === null && parent.grantBody.expiry !== null) {
      hard.push("adr.delegation_expiry_exceeded");
      break;
    }
  }

  if (hard.length > 0) {
    return {
      ok: false,
      effective_state: "Revoked",
      effective_scope: null,
      hard_invalid_reasons: hard,
      warnings: warn,
      ancestor_depth: ancestorDepth,
    };
  }

  // ── Cascade state from ancestors ───────────────────────────────────────
  // Evaluate each ancestor's chain state. Worst cascading state wins.
  // Priority: Revoked/Expired > Suspended > Active.
  // Each ancestor is evaluated in an isolated chain index so the chain
  // walker doesn't traverse grant→grant prev links.

  let cascadeState: AdrState = "Active";

  for (const ancestor of ancestors) {
    const iso = buildIsolatedChain(ancestor.receipt.id, treeIndex.byId);
    const ancestorChain = walkAdrChain(iso.tipId, iso.index, {
      ...(opts?.chainDepthLimit !== undefined && { depthLimit: opts.chainDepthLimit }),
      clock,
    });

    if (!ancestorChain.ok) {
      // Structurally invalid ancestor → treat as revoked.
      cascadeState = "Revoked";
      break;
    }

    if (
      ancestorChain.state === "Revoked" ||
      ancestorChain.state === "Expired"
    ) {
      // Terminal states take highest precedence — short-circuit.
      cascadeState = ancestorChain.state;
      break;
    }

    if (ancestorChain.state === "Suspended" && cascadeState === "Active") {
      cascadeState = "Suspended";
      // Don't break — a higher ancestor might be Revoked/Expired.
    }
  }

  // ── Evaluate this receipt's own chain state ────────────────────────────
  // Use an isolated chain index so the chain walker sees this grant as root.

  const selfIso = buildIsolatedChain(receiptId, treeIndex.byId);
  const selfChain = walkAdrChain(selfIso.tipId, selfIso.index, {
    ...(opts?.chainDepthLimit !== undefined && { depthLimit: opts.chainDepthLimit }),
    clock,
  });

  // Merge: worst of self state and cascade state.
  let effectiveState: AdrState;

  if (!selfChain.ok) {
    effectiveState = "Revoked";
  } else if (
    selfChain.state === "Revoked" ||
    selfChain.state === "Expired"
  ) {
    effectiveState = selfChain.state;
  } else if (
    cascadeState === "Revoked" ||
    cascadeState === "Expired"
  ) {
    effectiveState = cascadeState;
  } else if (
    selfChain.state === "Suspended" ||
    cascadeState === "Suspended"
  ) {
    effectiveState = "Suspended";
  } else {
    effectiveState = "Active";
  }

  return {
    ok: selfChain.ok && cascadeState === "Active",
    effective_state: effectiveState,
    effective_scope: selfChain.effective_scope,
    hard_invalid_reasons: [...selfChain.hard_invalid_reasons],
    warnings: [...selfChain.warnings],
    ancestor_depth: ancestorDepth,
  };
}
