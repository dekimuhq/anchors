/**
 * APR composition surface for ALR (spec §6.2 step 3 + §8 family composition).
 *
 * Distinct from `chain.ts`:
 *   - `chain.ts` walks the lineage DAG and supersession chain across all
 *     ALR receipts, terminating at APR-covered parents.
 *   - `composition.ts` (this module) focuses ONLY on the APR composition
 *     edges: it extracts and indexes the `parents[].parent_apr_id`
 *     references that connect an ALR receipt to its sibling APR provenance
 *     receipts.
 *
 * The two modules are intentionally complementary — callers walking lineage
 * use `chain.ts`; callers auditing APR coverage (how many parents have an
 * upstream APR receipt? which APR receipts does this ALR cite?) use this
 * module. Both share `AlrChainReceipt`.
 *
 * `successor` (carried on `superseded_by` bodies) is NOT a composition
 * edge — supersession is forward-time within the ALR family itself, not
 * a cross-family APR linkage. Composition therefore looks at `parents[]`
 * exclusively, mirroring spec §6.2 step 3.
 */

import type { AlrBody, AlrParentRef } from "./types.ts";
import type { AlrChainReceipt } from "./chain.ts";

// ── Per-body extraction ───────────────────────────────────────────────────────

export interface AprCompositionSummary {
  /**
   * Distinct, lexicographically-sorted APR receipt IDs cited by
   * `body.parents[].parent_apr_id`. Empty when body carries no lineage
   * (`superseded_by`, `disclosed`) or when every parent is APR-uncovered.
   */
  aprRefs: string[];
  /**
   * Parent refs whose `parent_apr_id` is set. These are the APR-covered
   * lineage edges — origin terminators per spec §6.2 step 3.
   */
  coveredParents: AlrParentRef[];
  /**
   * Parent refs whose `parent_apr_id` is `null`. These are the lineage
   * edges that the backward walker continues through.
   */
  uncoveredParents: AlrParentRef[];
}

/**
 * Decompose an ALR body's parent list into APR-covered and APR-uncovered
 * edges. For `superseded_by` and `disclosed` bodies (which carry no
 * lineage parents) all three fields come back empty.
 *
 * Pure — no I/O, no caller-supplied corpus needed.
 */
export function extractAprComposition(body: AlrBody): AprCompositionSummary {
  const parents =
    body.event_type === "derived_from" || body.event_type === "forked_from"
      ? body.parents
      : [];

  const coveredParents: AlrParentRef[] = [];
  const uncoveredParents: AlrParentRef[] = [];
  for (const p of parents) {
    if (p.parent_apr_id !== null) coveredParents.push(p);
    else uncoveredParents.push(p);
  }

  const aprRefSet = new Set<string>();
  for (const p of coveredParents) {
    if (p.parent_apr_id !== null) aprRefSet.add(p.parent_apr_id);
  }
  const aprRefs = Array.from(aprRefSet).sort();

  return { aprRefs, coveredParents, uncoveredParents };
}

// ── Cross-receipt reverse index ───────────────────────────────────────────────

/**
 * Map of `apr_receipt_id → ALR receipts that cite it via
 * `parents[].parent_apr_id`. Values are arrays (one APR receipt may be
 * cited by many ALR children). Order within each bucket matches the
 * caller's input order — deduplicated by `AlrChainReceipt.id` so each
 * citing receipt appears at most once per APR ref.
 */
export type AprReverseIndex = ReadonlyMap<string, readonly AlrChainReceipt[]>;

export function buildAprReverseIndex(
  receipts: readonly AlrChainReceipt[],
): AprReverseIndex {
  const out = new Map<string, AlrChainReceipt[]>();
  for (const r of receipts) {
    const summary = extractAprComposition(r.body);
    if (summary.aprRefs.length === 0) continue;
    for (const aprId of summary.aprRefs) {
      const bucket = out.get(aprId);
      if (bucket === undefined) {
        out.set(aprId, [r]);
        continue;
      }
      // Dedupe by id — the same receipt may cite an apr_id via two parents
      // (legal but rare); we surface it once.
      if (bucket.every((existing) => existing.id !== r.id)) bucket.push(r);
    }
  }
  return out;
}

// ── Coverage roll-up ──────────────────────────────────────────────────────────

export interface AprCoverageReport {
  /** Total lineage parents across all `derived_from` + `forked_from` receipts. */
  totalLineageParents: number;
  /** Number of those parents that carry a non-null `parent_apr_id`. */
  aprCoveredParents: number;
  /** Distinct APR receipt IDs cited across the corpus, lexicographically sorted. */
  citedAprIds: string[];
  /** ALR receipts that have ≥1 APR-covered parent. */
  citingReceipts: AlrChainReceipt[];
}

/**
 * Roll up APR-coverage statistics across a corpus. Useful for auditors
 * answering "what fraction of this dataset's lineage is APR-anchored?"
 * without walking the DAG.
 */
export function buildAprCoverageReport(
  receipts: readonly AlrChainReceipt[],
): AprCoverageReport {
  let totalLineageParents = 0;
  let aprCoveredParents = 0;
  const citedAprIds = new Set<string>();
  const citingReceipts: AlrChainReceipt[] = [];
  const seenCitingIds = new Set<string>();

  for (const r of receipts) {
    const summary = extractAprComposition(r.body);
    const lineageCount = summary.coveredParents.length + summary.uncoveredParents.length;
    totalLineageParents += lineageCount;
    aprCoveredParents += summary.coveredParents.length;
    for (const id of summary.aprRefs) citedAprIds.add(id);
    if (summary.aprRefs.length > 0 && !seenCitingIds.has(r.id)) {
      citingReceipts.push(r);
      seenCitingIds.add(r.id);
    }
  }

  return {
    totalLineageParents,
    aprCoveredParents,
    citedAprIds: Array.from(citedAprIds).sort(),
    citingReceipts,
  };
}
