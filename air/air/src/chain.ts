/**
 * Envelope-`prev` chain walker for AIR (spec §6.1 + §6.2 + D10-AIR-2 +
 * D10-AIR-3 + D10-AIR-4 + D10-AIR-7).
 *
 * Walks the linear `prev` chain back from a starting receipt to its chain
 * head — the receipt whose `event_type === "dpia.threshold_triggered"` —
 * then applies the AIR-specific cross-event invariants. Unlike ABR (where
 * the chain head is always `prev: null`), an AIR `dpia.threshold_triggered`
 * MAY have a non-null `prev` referencing a predecessor chain's
 * `dpia.reviewed` (re-DPIA inheritance, §6.2 rule 7). The walker therefore
 * stops at the first `dpia.threshold_triggered` encountered AND surfaces
 * the head's `prev` separately for the re-DPIA check.
 *
 * Per-hop invariants (linear walk):
 *   1. Reject cycles via a visited set keyed on envelope ID.
 *   2. Verify `iss` consistency — every hop must carry the same controller DID.
 *   3. Verify `body.air_receipt_id` parity (D10-AIR-2) — identical across
 *      every receipt in a single DPIA's lifecycle.
 *
 * Cross-event invariants (applied AFTER the walk, in oldest→newest order):
 *   4. `processing_activity_id` parity (§6.2 rule 3) — every event in the
 *      chain MUST carry the same `processing_activity_id`. Drift surfaces
 *      `processing_activity_drift` HARD-invalid.
 *   5. `processing_activity_hash` parity (§6.2 rule 3) — the hash committed
 *      at `dpia.threshold_triggered` MUST appear identical on every hop
 *      that carries the field (currently `threshold_triggered` alone in v1,
 *      but the check is forward-safe). Drift surfaces `ropa_snapshot_drift`
 *      HARD-invalid.
 *   6. Artifact-hash immutability (§6.2 rule 4 + D10-AIR-7) — the
 *      `dpia_artifact_hash` committed at the first `dpia.completed` MUST
 *      appear identical on every subsequent `dpia.completed` in the same
 *      chain. Drift surfaces `dpia_artifact_hash_drift` HARD-invalid.
 *   7. Prior-consultation gate (§6.2 rule 5 + D10-AIR-4) — when the most
 *      recent `dpia.completed` has `residual_risk_level === "high"`, the
 *      chain MUST pass through `dpia.prior_consultation_resolved` before
 *      any `dpia.processing_authorised`. Missing surfaces
 *      `art36_prior_consultation_skipped` HARD-invalid.
 *   8. Scope-rewrite gate (spec §4.2 — D10-AIR re-scope-after-finding) —
 *      a second `dpia.scope_locked` in the same chain without an
 *      intervening `dpia.reviewed` (review_outcome=material_change) surfaces
 *      `scope_rewrite_without_review` HARD-invalid.
 *   9. Re-DPIA inheritance (§6.2 rule 7) — when the head's `prev !== null`,
 *      the referenced predecessor MUST be a `dpia.reviewed` with
 *      `review_outcome ∈ {"material_change","superseded"}` AND must share
 *      the controller's `iss` (continuity invariant). When the predecessor
 *      is present in the index but mis-typed, `re_dpia_invalid_predecessor`
 *      HARD-invalid; when absent from the index, `re_dpia_predecessor_missing`
 *      informational (callers reconstruct from a partial corpus).
 *
 * Per-hop / cross-event warnings (informational — never invalidate):
 *  10. Review-window overdue (§6.2 rule 6) — when the caller's `now` is
 *      strictly later than `dpia.completed.review_due_at` AND no
 *      `dpia.reviewed` event has landed since, surface `dpia_review_overdue`.
 *  11. Prior-consultation overdue (§4.8) — when
 *      `dpia.prior_consultation_resolved.iat > prior_consultation_initiated.iat
 *      + 14 weeks` (8 + 6 max), surface `art36_consultation_overdue`.
 *  12. DPO commit drift (§4.3) — when at least two
 *      `dpia.dpo_advised` events in the same chain carry different
 *      `dpo_did_or_email_commit` values, surface `dpo_commit_drift`.
 *  13. Post-hoc completion (D10-AIR informational) — when a
 *      `dpia.completed` lands strictly later than the chain head's
 *      `processing_start_at`, surface `dpia_post_hoc_warning` (DPIAs are
 *      supposed to land before processing begins; legacy retrofits are
 *      legal but flagged).
 *  14. Voluntary high-risk without consultation (§5.5) — when the
 *      caller-supplied `opts.profile === "impact.voluntary"` AND the most
 *      recent unsuperseded `dpia.completed` carried
 *      `residual_risk_level === "high"` AND no
 *      `dpia.prior_consultation_initiated` followed it in the chain, surface
 *      `voluntary_high_risk_no_consultation`. Informational only — the
 *      `processing_authorised` path is still hard-invalidated by §6.2 rule 5
 *      (D10-AIR-4) via `art36_prior_consultation_skipped`.
 *
 * §C scope: this module surfaces structural chain state + the cross-event
 * rules above. §D TSA-mandate checks, §E subject-presence rule, §F profile
 * validators, and §G AER/ATR/ALR/APuR/ABR composition apply on top of the
 * walker's output in subsequent commits.
 */

import type { AirBody } from "./types.ts";
import {
  AIR_DEFAULT_DEPTH_LIMIT,
  AIR_DEPTH_LIMIT_MAX,
  AIR_DEPTH_LIMIT_MIN,
} from "./types.ts";

// ── Receipt shape consumed by the walker ──────────────────────────────────────

/**
 * Minimal receipt shape the walker needs. A real receipt is an
 * `Envelope<AirBody>`; the walker accepts anything carrying these fields so
 * callers can hand it a thin projection rather than the whole envelope.
 *
 * `iat` is read as an ISO 8601 string; the walker uses `Date.parse` for
 * deadline arithmetic. Callers minting AIR receipts from v1.2 envelopes
 * SHOULD pass `iat` directly through; the walker never normalises.
 *
 * `body` MUST already have passed `verifyAirBody` — the walker treats it as
 * a typed narrowing target and reads structural fields only.
 */
export interface AirChainReceipt {
  /** Envelope ID (ULID). Used as the key in the chain index. */
  id: string;
  /** Envelope-level controller DID. */
  iss: string;
  /** Envelope-level `iat` (ISO 8601). */
  iat: string;
  /** Envelope-level back-link to the prior receipt in this chain. */
  prev: string | null;
  /** Parsed AIR body. Caller is expected to have run `verifyAirBody` first. */
  body: AirBody;
}

// ── Index ─────────────────────────────────────────────────────────────────────

/**
 * Read-only index of receipts keyed by envelope `id`. Duplicate IDs are
 * resolved by keeping the first occurrence — the walker treats receipt IDs
 * as globally unique, so duplicates indicate caller-side corpus error and
 * are ignored to keep the walk deterministic.
 */
export interface AirChainIndex {
  readonly byId: ReadonlyMap<string, AirChainReceipt>;
}

export function buildAirChainIndex(
  receipts: readonly AirChainReceipt[],
): AirChainIndex {
  const m = new Map<string, AirChainReceipt>();
  for (const r of receipts) {
    if (!m.has(r.id)) m.set(r.id, r);
  }
  return { byId: m };
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface AirChainWalkOptions {
  /**
   * Max number of hops the walker will traverse. Defaults to
   * `AIR_DEFAULT_DEPTH_LIMIT`; values are clamped into
   * `[AIR_DEPTH_LIMIT_MIN, AIR_DEPTH_LIMIT_MAX]`.
   */
  depthLimit?: number;
  /**
   * Reference time for the `dpia_review_overdue` informational check
   * (§6.2 rule 6). Defaults to `new Date()`. Callers replaying historical
   * corpora pass a fixed instant.
   */
  now?: Date;
  /**
   * Optional profile id for the receipt under verification. Required for
   * the `voluntary_high_risk_no_consultation` informational check
   * (spec §5.5) — fires only when `profile === "impact.voluntary"` and the
   * most recent `dpia.completed` carried `residual_risk_level === "high"`
   * without any subsequent `dpia.prior_consultation_initiated`.
   *
   * When undefined, the voluntary warning is silently skipped (every other
   * cross-event rule is profile-agnostic and runs as before).
   */
  profile?: string;
}

function clampDepth(d: number | undefined): number {
  const v = d ?? AIR_DEFAULT_DEPTH_LIMIT;
  if (v < AIR_DEPTH_LIMIT_MIN) return AIR_DEPTH_LIMIT_MIN;
  if (v > AIR_DEPTH_LIMIT_MAX) return AIR_DEPTH_LIMIT_MAX;
  return v;
}

// ── Result ────────────────────────────────────────────────────────────────────

export interface AirChainWalkResult {
  /**
   * Ordered hops from the starting receipt back toward the chain head — the
   * first entry is the receipt named by `startId`, the last is the head.
   * Empty when `startId` is not in the index.
   */
  hops: AirChainReceipt[];
  /**
   * The chain head reached — the receipt whose `event_type ===
   * "dpia.threshold_triggered"` (or, if no such receipt is reached, the
   * receipt whose `prev === null`). `null` when the walk aborted early
   * (cycle, dangling, truncation) or when `startId` was not in the index.
   */
  head: AirChainReceipt | null;
  /** True iff the walker revisited an already-seen receipt ID. */
  cycle: boolean;
  /** True iff the walker hit `depthLimit` before reaching the chain head. */
  truncated: boolean;
  /** True iff a `prev` pointer referenced an envelope absent from the index. */
  dangling: boolean;
  /** True iff at least two hops carried different `iss` values. */
  iss_inconsistent: boolean;
  /**
   * True iff at least two hops carried different `body.air_receipt_id`
   * values (D10-AIR-2 violation).
   */
  air_receipt_id_inconsistent: boolean;
  /**
   * True iff the chain head's `body.event_type !== "dpia.threshold_triggered"`.
   * Only meaningful when `head !== null`.
   */
  chain_head_not_threshold_triggered: boolean;
  /**
   * The head's `prev`. Non-null indicates a re-DPIA chain (predecessor was a
   * `dpia.reviewed` with `review_outcome ∈ {"material_change","superseded"}`).
   * `null` when the head itself is the chain start, or when no head was
   * reached.
   */
  predecessor_id: string | null;
  /**
   * Cross-event rules — populated AFTER the linear walk completes when
   * `head !== null`. Empty when the walk did not reach a head.
   *
   * Hard-invalid reasons (D10-AIR-2/-3/-4/-7, §6.2 rules 3–7): mismatched
   * `processing_activity_id` / `processing_activity_hash`, DPIA artifact
   * drift, prior-consultation skip, scope-rewrite-without-review, invalid
   * re-DPIA predecessor.
   */
  hard_invalid_reasons: string[];
  /**
   * Informational warnings — never invalidate the chain. Includes
   * `dpia_review_overdue`, `art36_consultation_overdue`, `dpo_commit_drift`,
   * `dpia_post_hoc_warning`, `re_dpia_predecessor_missing`.
   */
  warnings: string[];
}

// ── Walker ────────────────────────────────────────────────────────────────────

/**
 * Walk the envelope-`prev` chain backward from `startId` to the chain head,
 * then apply the AIR cross-event rules. See module doc for the full list of
 * per-hop and cross-event invariants enforced.
 *
 * The walker never throws on caller-side corpus errors (missing receipts,
 * cycles). Every failure mode surfaces as a flag, a hard-invalid reason, or
 * a warning so the caller can render advisory or fail-hard at their
 * discretion.
 */
export function walkAirChain(
  startId: string,
  index: AirChainIndex,
  opts?: AirChainWalkOptions,
): AirChainWalkResult {
  const limit = clampDepth(opts?.depthLimit);
  const now = opts?.now ?? new Date();
  const profile = opts?.profile;

  const hops: AirChainReceipt[] = [];
  const visited = new Set<string>();

  let cursor: string | null = startId;
  let head: AirChainReceipt | null = null;
  let cycle = false;
  let truncated = false;
  let dangling = false;
  let iss_inconsistent = false;
  let air_receipt_id_inconsistent = false;

  let firstIss: string | null = null;
  let firstAirReceiptId: string | null = null;

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

    const arid = r.body.air_receipt_id;
    if (firstAirReceiptId === null) {
      firstAirReceiptId = arid;
    } else if (arid !== firstAirReceiptId) {
      air_receipt_id_inconsistent = true;
    }

    // Stop the walk at the chain head — the first dpia.threshold_triggered
    // encountered, OR (defensively) a hop whose prev === null. Re-DPIA chains
    // have threshold_triggered.prev !== null; rule 7 evaluation reads it
    // out of `predecessor_id`.
    if (r.body.event_type === "dpia.threshold_triggered") {
      head = r;
      break;
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

  const chain_head_not_threshold_triggered =
    head !== null && head.body.event_type !== "dpia.threshold_triggered";
  const predecessor_id = head?.prev ?? null;

  const hard_invalid_reasons: string[] = [];
  const warnings: string[] = [];

  if (head !== null) {
    evaluateCrossEventRules(
      hops,
      head,
      index,
      now,
      profile,
      hard_invalid_reasons,
      warnings,
    );
  }

  return {
    hops,
    head,
    cycle,
    truncated,
    dangling,
    iss_inconsistent,
    air_receipt_id_inconsistent,
    chain_head_not_threshold_triggered,
    predecessor_id,
    hard_invalid_reasons,
    warnings,
  };
}

// ── Cross-event rule pass ─────────────────────────────────────────────────────

function evaluateCrossEventRules(
  hops: readonly AirChainReceipt[],
  head: AirChainReceipt,
  index: AirChainIndex,
  now: Date,
  profile: string | undefined,
  hardReasons: string[],
  warnings: string[],
): void {
  // The walker returns hops in walk order (newest→head). Many rules are
  // easier to reason about in oldest→newest order; build that view once.
  const oldestFirst = [...hops].reverse();

  evaluateProcessingActivityParity(oldestFirst, hardReasons);
  evaluateRopaSnapshotParity(oldestFirst, hardReasons);
  evaluateDpiaArtifactImmutability(oldestFirst, hardReasons);
  evaluatePriorConsultationGate(oldestFirst, hardReasons);
  evaluateScopeRewriteGate(oldestFirst, hardReasons);
  evaluateReDpiaInheritance(head, index, hardReasons, warnings);
  evaluateReviewWindow(oldestFirst, now, warnings);
  evaluateArt36ConsultationOverdue(oldestFirst, warnings);
  evaluateDpoCommitDrift(oldestFirst, warnings);
  evaluateDpiaPostHoc(oldestFirst, warnings);
  evaluateVoluntaryHighRiskNoConsultation(oldestFirst, profile, warnings);
}

// §6.2 rule 3 (id half).
function evaluateProcessingActivityParity(
  hops: readonly AirChainReceipt[],
  errors: string[],
): void {
  if (hops.length === 0) return;
  const firstId = hops[0]!.body.processing_activity_id;
  for (let i = 1; i < hops.length; i++) {
    if (hops[i]!.body.processing_activity_id !== firstId) {
      errors.push("processing_activity_drift");
      return;
    }
  }
}

// §6.2 rule 3 (hash half).
function evaluateRopaSnapshotParity(
  hops: readonly AirChainReceipt[],
  errors: string[],
): void {
  // `processing_activity_hash` is required on `dpia.threshold_triggered`
  // only in v1; every other event pins the field null. The check is
  // forward-safe: if a future amendment lets the hash recur on later
  // hops, those values MUST equal the head's.
  let firstHash: string | null = null;
  for (const r of hops) {
    const body = r.body as unknown as Record<string, unknown>;
    const h = body.processing_activity_hash;
    if (h === null || h === undefined) continue;
    if (typeof h !== "string") continue;
    if (firstHash === null) {
      firstHash = h;
    } else if (h !== firstHash) {
      errors.push("ropa_snapshot_drift");
      return;
    }
  }
}

// §6.2 rule 4 (D10-AIR-7).
function evaluateDpiaArtifactImmutability(
  hops: readonly AirChainReceipt[],
  errors: string[],
): void {
  let firstHash: string | null = null;
  for (const r of hops) {
    if (r.body.event_type !== "dpia.completed") continue;
    const h = r.body.dpia_artifact_hash;
    if (firstHash === null) {
      firstHash = h;
    } else if (h !== firstHash) {
      errors.push("dpia_artifact_hash_drift");
      return;
    }
  }
}

// §6.2 rule 5 (D10-AIR-4).
function evaluatePriorConsultationGate(
  hops: readonly AirChainReceipt[],
  errors: string[],
): void {
  let lastCompletedHigh = false;
  let resolvedSeenSinceCompleted = false;

  for (const r of hops) {
    switch (r.body.event_type) {
      case "dpia.completed":
        lastCompletedHigh = r.body.residual_risk_level === "high";
        resolvedSeenSinceCompleted = false;
        break;
      case "dpia.prior_consultation_resolved":
        resolvedSeenSinceCompleted = true;
        break;
      case "dpia.processing_authorised":
        if (lastCompletedHigh && !resolvedSeenSinceCompleted) {
          errors.push("art36_prior_consultation_skipped");
          return;
        }
        break;
      case "dpia.reviewed":
        // A material-change review resets the "current completed" pointer
        // for the rest of the chain (a fresh dpia.completed is expected
        // before any subsequent terminal). Conservative: clear both flags.
        if (
          r.body.review_outcome === "material_change" ||
          r.body.review_outcome === "superseded"
        ) {
          lastCompletedHigh = false;
          resolvedSeenSinceCompleted = false;
        }
        break;
      default:
        // other events do not affect the gate
        break;
    }
  }
}

// Spec §4.2 — re-scope-after-finding.
function evaluateScopeRewriteGate(
  hops: readonly AirChainReceipt[],
  errors: string[],
): void {
  let scopeLockedSeen = false;
  let reviewMaterialSinceScopeLocked = false;

  for (const r of hops) {
    switch (r.body.event_type) {
      case "dpia.scope_locked":
        if (scopeLockedSeen && !reviewMaterialSinceScopeLocked) {
          errors.push("scope_rewrite_without_review");
          return;
        }
        scopeLockedSeen = true;
        reviewMaterialSinceScopeLocked = false;
        break;
      case "dpia.reviewed":
        if (
          r.body.review_outcome === "material_change" ||
          r.body.review_outcome === "superseded"
        ) {
          reviewMaterialSinceScopeLocked = true;
        }
        break;
      default:
        break;
    }
  }
}

// §6.2 rule 7.
function evaluateReDpiaInheritance(
  head: AirChainReceipt,
  index: AirChainIndex,
  errors: string[],
  warnings: string[],
): void {
  if (head.body.event_type !== "dpia.threshold_triggered") return;
  if (head.prev === null) return;

  const predecessor = index.byId.get(head.prev);
  if (predecessor === undefined) {
    warnings.push("re_dpia_predecessor_missing");
    return;
  }
  if (predecessor.body.event_type !== "dpia.reviewed") {
    errors.push("re_dpia_invalid_predecessor");
    return;
  }
  const outcome = predecessor.body.review_outcome;
  if (outcome !== "material_change" && outcome !== "superseded") {
    errors.push("re_dpia_invalid_predecessor");
    return;
  }
  if (predecessor.iss !== head.iss) {
    errors.push("re_dpia_invalid_predecessor");
    return;
  }
}

// §6.2 rule 6.
function evaluateReviewWindow(
  hops: readonly AirChainReceipt[],
  now: Date,
  warnings: string[],
): void {
  // Find the most recent `dpia.completed`; if no subsequent `dpia.reviewed`
  // landed AND `now > review_due_at`, surface `dpia_review_overdue`.
  let lastCompletedDueMs: number | null = null;
  let reviewedSinceCompleted = false;

  for (const r of hops) {
    if (r.body.event_type === "dpia.completed") {
      lastCompletedDueMs = Date.parse(r.body.review_due_at);
      reviewedSinceCompleted = false;
    } else if (r.body.event_type === "dpia.reviewed") {
      reviewedSinceCompleted = true;
    }
  }

  if (lastCompletedDueMs === null || Number.isNaN(lastCompletedDueMs)) return;
  if (reviewedSinceCompleted) return;
  if (now.getTime() > lastCompletedDueMs) {
    warnings.push("dpia_review_overdue");
  }
}

// Spec §4.8 — 8 + 6 weeks max.
const FOURTEEN_WEEKS_MS = 14 * 7 * 24 * 60 * 60 * 1000;

function evaluateArt36ConsultationOverdue(
  hops: readonly AirChainReceipt[],
  warnings: string[],
): void {
  let lastInitiatedMs: number | null = null;
  for (const r of hops) {
    if (r.body.event_type === "dpia.prior_consultation_initiated") {
      lastInitiatedMs = Date.parse(r.iat);
    } else if (r.body.event_type === "dpia.prior_consultation_resolved") {
      if (lastInitiatedMs === null || Number.isNaN(lastInitiatedMs)) continue;
      const resolvedMs = Date.parse(r.iat);
      if (Number.isNaN(resolvedMs)) continue;
      if (resolvedMs > lastInitiatedMs + FOURTEEN_WEEKS_MS) {
        warnings.push("art36_consultation_overdue");
        return;
      }
    }
  }
}

// Spec §4.3 — dpo_did_or_email_commit drift across multiple dpo_advised events.
function evaluateDpoCommitDrift(
  hops: readonly AirChainReceipt[],
  warnings: string[],
): void {
  let firstCommit: string | null = null;
  for (const r of hops) {
    if (r.body.event_type !== "dpia.dpo_advised") continue;
    const c = r.body.dpo_did_or_email_commit;
    if (firstCommit === null) {
      firstCommit = c;
    } else if (c !== firstCommit) {
      warnings.push("dpo_commit_drift");
      return;
    }
  }
}

// Spec §5.5 — voluntary DPIA hit residual high risk without Art. 36 consult.
function evaluateVoluntaryHighRiskNoConsultation(
  hops: readonly AirChainReceipt[],
  profile: string | undefined,
  warnings: string[],
): void {
  if (profile !== "impact.voluntary") return;

  // Find the most recent `dpia.completed` with residual_risk_level === "high".
  // After it, check whether any `dpia.prior_consultation_initiated` lands.
  // Spec §5.5: voluntary DPIAs reaching "high" SHOULD still pass through
  // prior_consultation_initiated; skipping surfaces this informational warning.
  // §5.5 is jurisdictionally about the DPIA result, not the trigger origin.
  let highCompletedSeen = false;
  let consultationAfterHigh = false;

  for (const r of hops) {
    if (
      r.body.event_type === "dpia.completed" &&
      r.body.residual_risk_level === "high"
    ) {
      highCompletedSeen = true;
      consultationAfterHigh = false;
    } else if (
      r.body.event_type === "dpia.completed" &&
      r.body.residual_risk_level !== "high"
    ) {
      // A later non-high completed supersedes — the chain rolled back to
      // an acceptable risk level (e.g. after material_change re-DPIA).
      highCompletedSeen = false;
      consultationAfterHigh = false;
    } else if (r.body.event_type === "dpia.prior_consultation_initiated") {
      consultationAfterHigh = true;
    }
  }

  if (highCompletedSeen && !consultationAfterHigh) {
    warnings.push("voluntary_high_risk_no_consultation");
  }
}

// D10-AIR informational — DPIA landed after processing started.
function evaluateDpiaPostHoc(
  hops: readonly AirChainReceipt[],
  warnings: string[],
): void {
  // Find threshold_triggered.processing_start_at and at least one
  // dpia.completed; surface when completed.iat > processing_start_at.
  let processingStartMs: number | null = null;
  for (const r of hops) {
    if (r.body.event_type === "dpia.threshold_triggered") {
      processingStartMs = Date.parse(r.body.processing_start_at);
      break;
    }
  }
  if (processingStartMs === null || Number.isNaN(processingStartMs)) return;

  for (const r of hops) {
    if (r.body.event_type !== "dpia.completed") continue;
    const completedMs = Date.parse(r.iat);
    if (Number.isNaN(completedMs)) continue;
    if (completedMs > processingStartMs) {
      warnings.push("dpia_post_hoc_warning");
      return;
    }
  }
}
