/**
 * Envelope-`prev` chain walker for ABR (spec §6.1 + §6.2 + D10-ABR-3 +
 * D10-ABR-5).
 *
 * Walks the linear `prev` chain back from a starting receipt to its chain
 * head, enforcing the ABR per-incident invariants:
 *
 *   1. Reject cycles via a visited set keyed on envelope ID.
 *   2. Verify `iss` consistency — every hop must carry the same controller DID
 *      (the same controller signs every receipt in the incident chain).
 *   3. Verify `body.incident_correlation_id` parity — D10-ABR-3 mandates that
 *      this id is identical across every receipt in the chain. Surfaces
 *      `incident_correlation_id_inconsistent` when the walker observes two
 *      different values across hops. The walker does NOT abort on this
 *      mismatch; the caller decides whether to render advisory or fail-hard.
 *   4. Verify the chain head is a `breach.detected` event — D10-ABR-5: the
 *      `prev: null` terminator of an incident chain is always the detection
 *      event. Surfaces `chain_head_not_detected` when the head's
 *      `event_type !== "breach.detected"`.
 *
 * Distinct from ANR's `chain.ts`:
 *   - ANR enforces policy-host consistency and resolves a translation branch.
 *   - ABR enforces incident_correlation_id parity and a detected-head check;
 *     there is no translation branch. Profile is per-chain (a single ABR
 *     chain carries one profile end-to-end); cross-profile parity for
 *     multi-jurisdiction incidents is a separate caller surface (join on
 *     `incident_correlation_id` across multiple walker runs).
 *
 * §C scope: this module surfaces structural chain state. §D TSA-mandate
 * checks, §E subject-presence rule, and §G AAR/ARR/ATR/AER/ANR composition
 * apply on top of the walker's output in subsequent commits.
 */

import type { AbrBody } from "./types.ts";
import {
  ABR_DEFAULT_DEPTH_LIMIT,
  ABR_DEPTH_LIMIT_MAX,
  ABR_DEPTH_LIMIT_MIN,
} from "./types.ts";

// ── Receipt shape consumed by the walker ──────────────────────────────────────

/**
 * Minimal receipt shape the walker needs. A real receipt is an
 * `Envelope<AbrBody>`; we accept anything carrying these fields so callers
 * can hand the walker a thin projection rather than the whole envelope.
 *
 * `iss` comes from the envelope-level field supplied by
 * `@dekimuhq/anchors-envelope`. `body` MUST already have passed
 * `verifyAbrBody` — the walker treats it as a typed narrowing target and
 * reads `body.incident_correlation_id` + `body.event_type` only.
 */
export interface AbrChainReceipt {
  /** Envelope ID (ULID). Used as the key in the chain index. */
  id: string;
  /** Envelope-level controller DID. */
  iss: string;
  /** Envelope-level back-link to the prior receipt in this chain. */
  prev: string | null;
  /** Parsed ABR body. Caller is expected to have run `verifyAbrBody` first. */
  body: AbrBody;
}

// ── Index ─────────────────────────────────────────────────────────────────────

/**
 * Read-only index of receipts keyed by envelope `id`. Duplicate IDs are
 * resolved by keeping the first occurrence — the walker treats receipt IDs
 * as globally unique, so duplicates indicate caller-side corpus error and
 * are ignored to keep the walk deterministic.
 */
export interface AbrChainIndex {
  readonly byId: ReadonlyMap<string, AbrChainReceipt>;
}

export function buildAbrChainIndex(
  receipts: readonly AbrChainReceipt[],
): AbrChainIndex {
  const m = new Map<string, AbrChainReceipt>();
  for (const r of receipts) {
    if (!m.has(r.id)) m.set(r.id, r);
  }
  return { byId: m };
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface AbrChainWalkOptions {
  /**
   * Max number of hops the walker will traverse. Defaults to
   * `ABR_DEFAULT_DEPTH_LIMIT`; values are clamped into
   * `[ABR_DEPTH_LIMIT_MIN, ABR_DEPTH_LIMIT_MAX]`.
   */
  depthLimit?: number;
}

function clampDepth(d: number | undefined): number {
  const v = d ?? ABR_DEFAULT_DEPTH_LIMIT;
  if (v < ABR_DEPTH_LIMIT_MIN) return ABR_DEPTH_LIMIT_MIN;
  if (v > ABR_DEPTH_LIMIT_MAX) return ABR_DEPTH_LIMIT_MAX;
  return v;
}

// ── Result ────────────────────────────────────────────────────────────────────

export interface AbrChainWalkResult {
  /**
   * Ordered hops from the starting receipt back toward the chain head — the
   * first entry is the receipt named by `startId`. Empty when `startId` is
   * not in the index.
   */
  hops: AbrChainReceipt[];
  /**
   * The chain head reached — the last receipt in `hops` whose `prev === null`.
   * `null` when the walk aborted early (cycle, dangling, truncation) or
   * when `startId` was not in the index.
   */
  head: AbrChainReceipt | null;
  /** True iff the walker revisited an already-seen receipt ID. */
  cycle: boolean;
  /** True iff the walker hit `depthLimit` before reaching the chain head. */
  truncated: boolean;
  /** True iff a `prev` pointer referenced an envelope absent from the index. */
  dangling: boolean;
  /**
   * True iff at least two hops carried different `iss` values. The walker
   * does NOT stop on iss mismatch; this flag surfaces it for the caller.
   */
  iss_inconsistent: boolean;
  /**
   * True iff at least two hops carried different `body.incident_correlation_id`
   * values (D10-ABR-3 violation). The walker does NOT stop on this mismatch;
   * this flag surfaces it for the caller.
   */
  incident_correlation_id_inconsistent: boolean;
  /**
   * True iff the chain head's `body.event_type !== "breach.detected"`
   * (D10-ABR-5 violation). Only meaningful when `head !== null`; false when
   * the walk did not reach a head.
   */
  chain_head_not_detected: boolean;
}

// ── Walker ────────────────────────────────────────────────────────────────────

/**
 * Walk the envelope-`prev` chain backward from `startId` to the chain head.
 * See module doc for the ABR per-incident invariants applied per hop.
 *
 * The walker never throws on caller-side corpus errors (missing receipts,
 * cycles). Every failure mode surfaces as a result flag so the caller can
 * render it advisory or fail-hard at their discretion.
 */
export function walkAbrChain(
  startId: string,
  index: AbrChainIndex,
  opts?: AbrChainWalkOptions,
): AbrChainWalkResult {
  const limit = clampDepth(opts?.depthLimit);

  const hops: AbrChainReceipt[] = [];
  const visited = new Set<string>();

  let cursor: string | null = startId;
  let head: AbrChainReceipt | null = null;
  let cycle = false;
  let truncated = false;
  let dangling = false;
  let iss_inconsistent = false;
  let incident_correlation_id_inconsistent = false;

  let firstIss: string | null = null;
  let firstIncidentId: string | null = null;

  while (cursor !== null) {
    if (visited.has(cursor)) {
      cycle = true;
      head = null;
      break;
    }
    visited.add(cursor);

    const r = index.byId.get(cursor);
    if (r === undefined) {
      dangling = true;
      head = null;
      break;
    }
    hops.push(r);

    if (firstIss === null) {
      firstIss = r.iss;
    } else if (r.iss !== firstIss) {
      iss_inconsistent = true;
    }

    const incidentId = r.body.incident_correlation_id;
    if (firstIncidentId === null) {
      firstIncidentId = incidentId;
    } else if (incidentId !== firstIncidentId) {
      incident_correlation_id_inconsistent = true;
    }

    if (r.prev === null) {
      head = r;
      break;
    }

    if (hops.length >= limit) {
      truncated = true;
      head = null;
      break;
    }

    cursor = r.prev;
  }

  const chain_head_not_detected =
    head !== null && head.body.event_type !== "breach.detected";

  return {
    hops,
    head,
    cycle,
    truncated,
    dangling,
    iss_inconsistent,
    incident_correlation_id_inconsistent,
    chain_head_not_detected,
  };
}
