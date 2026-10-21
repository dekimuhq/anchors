/**
 * Envelope-`prev` chain walker for ANR (spec §6.1 + §6.2).
 *
 * Walks the linear `prev` chain back from a starting receipt to its chain
 * head, enforcing the three §6.2 invariants:
 *
 *   1. Reject cycles via a visited set keyed on envelope ID.
 *   2. Verify `iss` consistency — every hop must carry the same controller DID.
 *   3. Verify `policy_uri` host consistency — every hop's `policy_uri` MUST
 *      resolve to the same authority domain. Hops with a `null` `policy_uri`
 *      are skipped (no comparison made).
 *
 * Per D10-ANR-5 + §4.5 a `notice.translated` receipt has `prev: null`. When
 * the walk terminates on a translation receipt, the walker performs a single
 * translation-branch resolution against `body.base_anr_id`. If the base
 * receipt is absent from the supplied index, the walker surfaces
 * `base_unresolvable` as a warning — not an error. Erasure of the base
 * notice under Art. 17 must not poison the translation branch (§6.2 step 3).
 *
 * The walker is receipt-store agnostic: callers build an `AnrChainIndex`
 * keyed on envelope ID from whatever store they hold (memory, DB, IPFS) and
 * hand it in. The walker holds no references to envelopes beyond the
 * iteration scope.
 *
 * Distinct from ALR's `chain.ts`:
 *   - ALR walks via body `parents[]` / `successor` (DAG).
 *   - ANR walks via envelope `prev` (linear) with one translation-branch
 *     sidecar pointer.
 *
 * §C scope: this module surfaces structural chain state. §D TSA-mandate
 * checks, §E subject-presence rule, and §G ACR composition apply on top of
 * the walker's output in subsequent commits.
 */

import type { AnrBody, AnrTranslatedBody } from "./types.ts";
import {
  ANR_DEFAULT_DEPTH_LIMIT,
  ANR_DEPTH_LIMIT_MAX,
  ANR_DEPTH_LIMIT_MIN,
} from "./types.ts";

// ── Receipt shape consumed by the walker ──────────────────────────────────────

/**
 * Minimal receipt shape the walker needs. A real receipt is an
 * `Envelope<AnrBody>`; we accept anything carrying these fields so callers
 * can hand the walker a thin projection rather than the whole envelope.
 *
 * `iss` and `policy_uri` come from the envelope-level fields supplied by
 * `@dekimuhq/anchors-envelope`. `body` MUST already have passed
 * `verifyAnrBody` — the walker treats it as a typed narrowing target.
 */
export interface AnrChainReceipt {
  /** Envelope ID (ULID). Used as the key in the chain index. */
  id: string;
  /** Envelope-level controller DID. */
  iss: string;
  /** Envelope-level policy URI, or `null` when the receipt omits it. */
  policy_uri: string | null;
  /** Envelope-level back-link to the prior receipt in this chain. */
  prev: string | null;
  /** Parsed ANR body. Caller is expected to have run `verifyAnrBody` first. */
  body: AnrBody;
}

// ── Index ─────────────────────────────────────────────────────────────────────

/**
 * Read-only index of receipts keyed by envelope `id`. Duplicate IDs are
 * resolved by keeping the first occurrence — the walker treats receipt IDs
 * as globally unique, so duplicates indicate caller-side corpus error and
 * are ignored to keep the walk deterministic.
 */
export interface AnrChainIndex {
  readonly byId: ReadonlyMap<string, AnrChainReceipt>;
}

export function buildAnrChainIndex(
  receipts: readonly AnrChainReceipt[],
): AnrChainIndex {
  const m = new Map<string, AnrChainReceipt>();
  for (const r of receipts) {
    if (!m.has(r.id)) m.set(r.id, r);
  }
  return { byId: m };
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface AnrChainWalkOptions {
  /**
   * Max number of hops the walker will traverse. Defaults to
   * `ANR_DEFAULT_DEPTH_LIMIT`; values are clamped into
   * `[ANR_DEPTH_LIMIT_MIN, ANR_DEPTH_LIMIT_MAX]`.
   */
  depthLimit?: number;
}

function clampDepth(d: number | undefined): number {
  const v = d ?? ANR_DEFAULT_DEPTH_LIMIT;
  if (v < ANR_DEPTH_LIMIT_MIN) return ANR_DEPTH_LIMIT_MIN;
  if (v > ANR_DEPTH_LIMIT_MAX) return ANR_DEPTH_LIMIT_MAX;
  return v;
}

// ── Result ────────────────────────────────────────────────────────────────────

export interface AnrChainWalkResult {
  /**
   * Ordered hops from the starting receipt back toward the chain head — the
   * first entry is the receipt named by `startId`. Empty when `startId` is
   * not in the index.
   */
  hops: AnrChainReceipt[];
  /**
   * The chain head reached — the last receipt in `hops` whose `prev === null`.
   * `null` when the walk aborted early (cycle, dangling, truncation) or
   * when `startId` was not in the index.
   */
  head: AnrChainReceipt | null;
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
   * True iff at least two hops carried `policy_uri` values whose URL host
   * components differ. Hops with `policy_uri === null` are skipped. The
   * walker does NOT stop on host mismatch.
   */
  policy_host_inconsistent: boolean;
  /**
   * True iff at least one `policy_uri` value in the chain failed `new URL()`
   * parsing. Mutually exclusive with `policy_host_inconsistent`: the walker
   * cannot reason about host equality when the URL is unparseable.
   */
  policy_uri_unparseable: boolean;
  /**
   * Translation-branch resolution. Populated only when the chain head is a
   * `notice.translated` receipt (or when `startId` itself is a translation
   * receipt with `prev: null`). `null` otherwise.
   */
  translation_branch: TranslationBranchResolution | null;
}

export interface TranslationBranchResolution {
  /** The translation receipt at the chain's branching point. */
  translation: AnrChainReceipt;
  /** The `base_anr_id` carried in the translation body. */
  base_anr_id: string;
  /**
   * The base receipt looked up in the index. `null` when the base is not in
   * the supplied corpus — paired with `base_unresolvable === true`. Per
   * §6.2 step 3 this is a warning, not an error: the base may have been
   * erased under Art. 17 separately from its translations.
   */
  base: AnrChainReceipt | null;
  /** True iff `base === null`. */
  base_unresolvable: boolean;
}

// ── Walker ────────────────────────────────────────────────────────────────────

/**
 * Walk the envelope-`prev` chain backward from `startId` to the chain head.
 * See module doc for the §6.2 invariants applied per hop.
 *
 * The walker never throws on caller-side corpus errors (missing receipts,
 * cycles, unparseable URLs). Every failure mode surfaces as a result flag
 * so the caller can render it advisory or fail-hard at their discretion.
 */
export function walkAnrChain(
  startId: string,
  index: AnrChainIndex,
  opts?: AnrChainWalkOptions,
): AnrChainWalkResult {
  const limit = clampDepth(opts?.depthLimit);

  const hops: AnrChainReceipt[] = [];
  const visited = new Set<string>();

  let cursor: string | null = startId;
  let head: AnrChainReceipt | null = null;
  let cycle = false;
  let truncated = false;
  let dangling = false;
  let iss_inconsistent = false;
  let policy_host_inconsistent = false;
  let policy_uri_unparseable = false;

  let firstIss: string | null = null;
  let firstHost: string | null = null;
  let firstHostSet = false;

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

    if (r.policy_uri !== null) {
      const host = tryParseHost(r.policy_uri);
      if (host === null) {
        policy_uri_unparseable = true;
      } else if (!firstHostSet) {
        firstHost = host;
        firstHostSet = true;
      } else if (host !== firstHost) {
        policy_host_inconsistent = true;
      }
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

  const translation_branch = resolveTranslationBranch(head, index);

  return {
    hops,
    head,
    cycle,
    truncated,
    dangling,
    iss_inconsistent,
    policy_host_inconsistent,
    policy_uri_unparseable,
    translation_branch,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function tryParseHost(uri: string): string | null {
  try {
    return new URL(uri).host;
  } catch {
    return null;
  }
}

function resolveTranslationBranch(
  head: AnrChainReceipt | null,
  index: AnrChainIndex,
): TranslationBranchResolution | null {
  if (head === null) return null;
  if (head.body.event_type !== "notice.translated") return null;

  const tBody = head.body as AnrTranslatedBody;
  const baseId = tBody.base_anr_id;
  const base = index.byId.get(baseId) ?? null;

  return {
    translation: head,
    base_anr_id: baseId,
    base,
    base_unresolvable: base === null,
  };
}
