/**
 * Forward + backward chain walkers for ALR (spec §6.1 + §6.2).
 *
 * Operates on a caller-supplied corpus of ALR receipts. The walker is
 * receipt-store agnostic: callers build a `ChainIndex` from whatever store
 * they hold (memory, DB, IPFS) and hand it in.
 *
 * - Forward walk follows the supersession chain (event_type=`superseded_by`)
 *   from a starting artifact to its current version.
 * - Backward walk produces a derivation DAG by following
 *   `derived_from`/`forked_from` `parents[]` edges. Terminates at parents
 *   that carry a `parent_apr_id` (APR is the origin terminator, §6.2 step 3).
 *
 * Cycle detection and depth limits are enforced per spec §6.2 step 4 + the
 * depth-limit constants exported from `./types.ts`.
 */

import type { AlrBody, AlrParentRef } from "./types.ts";
import {
  ALR_DEFAULT_DEPTH_LIMIT,
  ALR_DEPTH_LIMIT_MAX,
  ALR_DEPTH_LIMIT_MIN,
} from "./types.ts";

// ── Receipt shape consumed by the walkers ─────────────────────────────────────

/**
 * Minimal receipt shape the walkers need. A real receipt is an
 * `Envelope<AlrBody>`; we accept anything carrying these three fields so
 * callers can pass through their own envelope wrapper without coupling
 * the walker to the v=2 envelope module.
 */
export interface AlrChainReceipt {
  /** Envelope ID (ULID). Used for stable identity in cycle warnings. */
  id: string;
  /** Parsed ALR body. Caller is expected to have run `verifyAlrBody` first. */
  body: AlrBody;
}

// ── Index ─────────────────────────────────────────────────────────────────────

/**
 * Read-only index of receipts keyed by `body.artifact_hash`. Within each
 * bucket receipts are sorted by `body.event_at` newest-first so the forward
 * walker can pick the "newest receipt for A" per spec §6.2 step 1 in O(1).
 */
export interface ChainIndex {
  byArtifactHash: ReadonlyMap<string, readonly AlrChainReceipt[]>;
}

export function buildChainIndex(receipts: readonly AlrChainReceipt[]): ChainIndex {
  const m = new Map<string, AlrChainReceipt[]>();
  for (const r of receipts) {
    const k = r.body.artifact_hash;
    const arr = m.get(k);
    if (arr === undefined) m.set(k, [r]);
    else arr.push(r);
  }
  for (const arr of m.values()) {
    arr.sort((a, b) => {
      const at = Date.parse(b.body.event_at) - Date.parse(a.body.event_at);
      if (at !== 0) return at;
      // Stable secondary on ID to keep ordering deterministic for equal times.
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
  }
  return { byArtifactHash: m };
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface ChainWalkOptions {
  /**
   * Max traversal hops (forward) or DAG nodes (backward). Defaults to
   * `ALR_DEFAULT_DEPTH_LIMIT`; clamped to `[ALR_DEPTH_LIMIT_MIN,
   * ALR_DEPTH_LIMIT_MAX]` per spec §6.2.
   */
  depthLimit?: number;
}

function clampDepth(d: number | undefined): number {
  const v = d ?? ALR_DEFAULT_DEPTH_LIMIT;
  if (v < ALR_DEPTH_LIMIT_MIN) return ALR_DEPTH_LIMIT_MIN;
  if (v > ALR_DEPTH_LIMIT_MAX) return ALR_DEPTH_LIMIT_MAX;
  return v;
}

// ── Forward walk ──────────────────────────────────────────────────────────────

export interface ForwardWalkResult {
  /** Ordered hops from start to current — first entry is the starting receipt. */
  hops: AlrChainReceipt[];
  /** Last receipt reached; `null` only if the start was not in the index. */
  current: AlrChainReceipt | null;
  /** True if walk hit the depth limit before terminating. */
  truncated: boolean;
  /** True if a cycle was detected and the walk aborted at the revisit. */
  cycle: boolean;
  /** True if the next hop's artifact_hash had no receipt in the index. */
  dangling: boolean;
}

/**
 * Walk forward from a starting artifact_hash to its current version per spec
 * §6.2 forward-walk rules. Returns the ordered hop list, the terminal receipt,
 * and flags for truncation / cycle / dangling-pointer.
 */
export function forwardWalk(
  startArtifactHash: string,
  index: ChainIndex,
  opts?: ChainWalkOptions,
): ForwardWalkResult {
  const limit = clampDepth(opts?.depthLimit);
  const hops: AlrChainReceipt[] = [];
  const visited = new Set<string>();

  let cursor: string | null = startArtifactHash;
  let current: AlrChainReceipt | null = null;
  let truncated = false;
  let cycle = false;
  let dangling = false;

  while (cursor !== null) {
    if (visited.has(cursor)) {
      cycle = true;
      break;
    }
    visited.add(cursor);

    const bucket = index.byArtifactHash.get(cursor);
    if (bucket === undefined || bucket.length === 0) {
      dangling = true;
      break;
    }
    const next = bucket[0]!; // Newest receipt for this artifact (§6.2 step 1).
    hops.push(next);
    current = next;

    if (hops.length >= limit) {
      // Only mark truncated when the chain would continue past the cap.
      if (next.body.event_type === "superseded_by") truncated = true;
      break;
    }

    if (next.body.event_type === "superseded_by") {
      cursor = next.body.successor.artifact_hash;
    } else {
      cursor = null;
    }
  }

  return { hops, current, truncated, cycle, dangling };
}

// ── Backward walk ─────────────────────────────────────────────────────────────

export interface DagEdge {
  /** Parent reference as carried on the child receipt. */
  parentRef: AlrParentRef;
  /** Sub-DAG rooted at `parentRef.artifact_hash`. Empty when terminator. */
  node: DagNode | null;
  /**
   * True iff `parentRef.parent_apr_id !== null`; per §6.2 step 3, APR coverage
   * is the origin terminator and the walker does not recurse further.
   */
  aprTerminator: boolean;
  /** True iff the index has no lineage receipts for `parentRef.artifact_hash`. */
  dangling: boolean;
}

export interface DagNode {
  /** Artifact hash this node represents. */
  artifactHash: string;
  /**
   * Lineage receipts (event_type `derived_from` or `forked_from`) found at
   * this artifact, in newest-first order. May be empty for the starting hash
   * if the artifact has only supersession or disclosure receipts.
   */
  lineageReceipts: AlrChainReceipt[];
  /** Edges to parent artifacts. */
  parents: DagEdge[];
}

export interface BackwardWalkResult {
  root: DagNode;
  /** True if walk hit the depth cap (node count) before exhausting parents. */
  truncated: boolean;
  /** True if a cycle was detected and skipped during traversal. */
  cycle: boolean;
}

const LINEAGE_EVENT_TYPES = new Set(["derived_from", "forked_from"]);

/**
 * Walk backward from a starting artifact_hash to produce a lineage DAG per
 * spec §6.2 backward-walk rules. Visited-set on `(artifact_hash, event_type)`
 * pairs matches the spec exactly. APR-covered parents (parent_apr_id != null)
 * terminate the recursion per step 3.
 */
export function backwardWalk(
  startArtifactHash: string,
  index: ChainIndex,
  opts?: ChainWalkOptions,
): BackwardWalkResult {
  const limit = clampDepth(opts?.depthLimit);
  const visited = new Set<string>();
  const state = { nodes: 0, truncated: false, cycle: false };

  const root = visit(startArtifactHash, index, visited, state, limit);
  return { root, truncated: state.truncated, cycle: state.cycle };
}

function visit(
  artifactHash: string,
  index: ChainIndex,
  visited: Set<string>,
  state: { nodes: number; truncated: boolean; cycle: boolean },
  limit: number,
): DagNode {
  state.nodes += 1;
  const bucket = index.byArtifactHash.get(artifactHash) ?? [];
  const lineageReceipts = bucket.filter((r) => LINEAGE_EVENT_TYPES.has(r.body.event_type));

  const node: DagNode = {
    artifactHash,
    lineageReceipts,
    parents: [],
  };

  for (const r of lineageReceipts) {
    // §6.2 step 4: visited-set on (artifact_hash, event_type) pairs.
    const visitKey = `${artifactHash} ${r.body.event_type}`;
    if (visited.has(visitKey)) {
      state.cycle = true;
      continue;
    }
    visited.add(visitKey);

    // `body.parents` is statically typed by event_type — both lineage variants
    // carry a `parents: AlrParentRef[]` array (length ≥1 derived_from, =1 forked_from).
    const parents =
      r.body.event_type === "derived_from" || r.body.event_type === "forked_from"
        ? r.body.parents
        : [];

    for (const pref of parents) {
      const aprTerminator = pref.parent_apr_id !== null;
      if (aprTerminator) {
        node.parents.push({ parentRef: pref, node: null, aprTerminator: true, dangling: false });
        continue;
      }

      if (state.nodes >= limit) {
        state.truncated = true;
        node.parents.push({ parentRef: pref, node: null, aprTerminator: false, dangling: false });
        continue;
      }

      const child = visit(pref.artifact_hash, index, visited, state, limit);
      const dangling = child.lineageReceipts.length === 0 && child.parents.length === 0;
      node.parents.push({ parentRef: pref, node: child, aprTerminator: false, dangling });
    }
  }

  return node;
}
