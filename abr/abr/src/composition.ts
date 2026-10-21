/**
 * Cross-family composition surface for ABR (spec §8 + audit-fix C5).
 *
 * Distinct from `chain.ts`:
 *   - `chain.ts` walks the intra-family envelope-`prev` chain enforcing
 *     incident_correlation_id parity and the detected-head invariant.
 *   - `composition.ts` (this module) handles cross-family edges: the five
 *     audit-fix C5 composition fields binding an incident to sibling
 *     ARR / ATR / AER / ANR / AAR receipts.
 *
 * Composition matrix (spec §8 + audit-fix C5):
 *
 * | ABR event               | Field                              | Target family               | Cardinality      |
 * |-------------------------|------------------------------------|-----------------------------|------------------|
 * | `breach.detected`       | `affected_aer_ids`                 | AER (`ar.evaluation.v1`)    | 0..n             |
 * | `breach.contained`      | `containment_remediation_arr_ids`  | ARR (`ar.erasure.v1` /      | 0..n             |
 * |                         |                                    |  `ar.anonymization.v1`)     |                  |
 * | `breach.contained`      | `transfer_suspension_atr_ids`      | ATR (`ar.transfer.v1`)      | 0..n             |
 * | `breach.dpa_notified`   | `qes_aar_id`                       | AAR (`ar.attestation.v1`)   | 0..1             |
 * | `breach.closed`         | `post_breach_anr_id`               | ANR (`ar.notice.v1`)        | 0..1             |
 *
 * The module is pure: no I/O, no caller-supplied verifier callbacks, no
 * cross-family resolution. Auditors hand in a corpus of ABR receipts and
 * receive deterministic per-target reverse indexes plus a coverage roll-up.
 *
 * Reverse-direction edges (ARR → ABR, ANR → ABR, etc.) live in the target
 * family's `composition.ts` — this module surfaces only the ABR side of
 * each link. Cross-claim_type validation (e.g. confirming a cited ARR
 * receipt actually carries `claim_type: "ar.erasure.v1"`) is intentionally
 * out of scope per the family pattern; that check belongs to a future
 * cross-verifier pass that holds both corpora simultaneously.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/abr §8.
 */

import type { AbrBody } from "./types.ts";
import type { AbrChainReceipt } from "./chain.ts";

// ── Per-body extraction ───────────────────────────────────────────────────────

export interface AbrCompositionLinks {
  /** ARR receipt ids cited on `breach.contained.containment_remediation_arr_ids` (§8.3). */
  containmentRemediationArrIds: readonly string[];
  /** ATR receipt ids cited on `breach.contained.transfer_suspension_atr_ids` (§8.3). */
  transferSuspensionAtrIds: readonly string[];
  /** AER receipt ids cited on `breach.detected.affected_aer_ids` (§8.4). */
  affectedAerIds: readonly string[];
  /** ANR receipt id cited on `breach.closed.post_breach_anr_id` (§8.5). */
  postBreachAnrId: string | null;
  /** AAR receipt id cited on `breach.dpa_notified.qes_aar_id` (§8.2). */
  qesAarId: string | null;
}

const EMPTY_LINKS: AbrCompositionLinks = Object.freeze({
  containmentRemediationArrIds: [],
  transferSuspensionAtrIds: [],
  affectedAerIds: [],
  postBreachAnrId: null,
  qesAarId: null,
});

/**
 * Pull every cross-family composition reference out of an ABR body.
 *
 * Returns a fully-populated `AbrCompositionLinks` value for any event_type;
 * fields that do not apply to the event come back as `[]` or `null`. The
 * fixed shape lets callers iterate without per-event-type dispatch.
 *
 * Pure — no resolution, no validation of cited receipts' existence or
 * claim_type. Defensive against bodies whose `*_ids` array fields are
 * explicitly empty arrays (`[]`) vs `null`; both yield `[]` in the output
 * to collapse the auditor surface.
 */
export function extractAbrComposition(body: AbrBody): AbrCompositionLinks {
  switch (body.event_type) {
    case "breach.detected": {
      const aer = body.affected_aer_ids;
      return {
        ...EMPTY_LINKS,
        affectedAerIds: aer === null ? [] : aer,
      };
    }
    case "breach.contained": {
      const arr = body.containment_remediation_arr_ids;
      const atr = body.transfer_suspension_atr_ids;
      return {
        ...EMPTY_LINKS,
        containmentRemediationArrIds: arr === null ? [] : arr,
        transferSuspensionAtrIds: atr === null ? [] : atr,
      };
    }
    case "breach.dpa_notified": {
      return {
        ...EMPTY_LINKS,
        qesAarId: body.qes_aar_id,
      };
    }
    case "breach.closed": {
      return {
        ...EMPTY_LINKS,
        postBreachAnrId: body.post_breach_anr_id,
      };
    }
    default:
      return EMPTY_LINKS;
  }
}

// ── Per-target reverse indexes ────────────────────────────────────────────────

/**
 * Map of `target_receipt_id → ABR receipts that cite it`. Used uniformly
 * for ARR, ATR, AER, ANR, and AAR target families. Buckets are arrays;
 * the same ABR receipt appears at most once per bucket (deduplicated by
 * envelope id) so callers can count citing receipts without re-deduping.
 */
export type AbrReverseIndex = ReadonlyMap<string, readonly AbrChainReceipt[]>;

export interface AbrReverseIndexes {
  /** ARR id → citing `breach.contained` ABR receipts (via `containment_remediation_arr_ids`). */
  arrIndex: AbrReverseIndex;
  /** ATR id → citing `breach.contained` ABR receipts (via `transfer_suspension_atr_ids`). */
  atrIndex: AbrReverseIndex;
  /** AER id → citing `breach.detected` ABR receipts (via `affected_aer_ids`). */
  aerIndex: AbrReverseIndex;
  /** ANR id → citing `breach.closed` ABR receipts (via `post_breach_anr_id`). */
  anrIndex: AbrReverseIndex;
  /** AAR id → citing `breach.dpa_notified` ABR receipts (via `qes_aar_id`). */
  aarIndex: AbrReverseIndex;
}

function pushUnique(
  map: Map<string, AbrChainReceipt[]>,
  key: string,
  receipt: AbrChainReceipt,
): void {
  if (key.length === 0) return;
  const bucket = map.get(key);
  if (bucket === undefined) {
    map.set(key, [receipt]);
    return;
  }
  if (bucket.every((existing) => existing.id !== receipt.id)) bucket.push(receipt);
}

/**
 * Build the five per-target reverse indexes for a corpus of ABR receipts.
 * Receipts that declare no composition references (every other event_type,
 * plus `breach.contained` with empty / null arrays, etc.) contribute no
 * entries.
 *
 * Pure — input order determines per-bucket order; output ordering is
 * deterministic for a given input.
 */
export function buildAbrReverseIndexes(
  receipts: readonly AbrChainReceipt[],
): AbrReverseIndexes {
  const arr = new Map<string, AbrChainReceipt[]>();
  const atr = new Map<string, AbrChainReceipt[]>();
  const aer = new Map<string, AbrChainReceipt[]>();
  const anr = new Map<string, AbrChainReceipt[]>();
  const aar = new Map<string, AbrChainReceipt[]>();

  for (const r of receipts) {
    const links = extractAbrComposition(r.body);
    for (const id of links.containmentRemediationArrIds) pushUnique(arr, id, r);
    for (const id of links.transferSuspensionAtrIds) pushUnique(atr, id, r);
    for (const id of links.affectedAerIds) pushUnique(aer, id, r);
    if (links.postBreachAnrId !== null) pushUnique(anr, links.postBreachAnrId, r);
    if (links.qesAarId !== null) pushUnique(aar, links.qesAarId, r);
  }

  return {
    arrIndex: arr,
    atrIndex: atr,
    aerIndex: aer,
    anrIndex: anr,
    aarIndex: aar,
  };
}

// ── Coverage roll-up ──────────────────────────────────────────────────────────

export interface AbrCoverageReport {
  /** Total ABR receipts in the input corpus. */
  totalAbrReceipts: number;
  /** Distinct `incident_correlation_id` values, sorted lexicographically. */
  incidentIds: string[];

  /** ARR ids cited via `containment_remediation_arr_ids`, sorted. */
  citedArrIds: string[];
  /** ATR ids cited via `transfer_suspension_atr_ids`, sorted. */
  citedAtrIds: string[];
  /** AER ids cited via `affected_aer_ids`, sorted. */
  citedAerIds: string[];
  /** ANR ids cited via `post_breach_anr_id`, sorted. */
  citedAnrIds: string[];
  /** AAR ids cited via `qes_aar_id`, sorted. */
  citedAarIds: string[];

  /**
   * Incident ids whose `breach.detected` event declared ≥1 `affected_aer_ids`
   * (sorted). Answers: "which incidents bind to AI-Act high-risk systems?".
   */
  incidentsWithAerCoverage: string[];
  /**
   * Incident ids whose `breach.contained` event declared ≥1 ARR or ATR
   * composition reference (sorted). Answers: "which incidents tie
   * containment to subject-data outcomes or transfer suspensions?".
   */
  incidentsWithContainmentComposition: string[];
  /**
   * Incident ids whose `breach.closed` event declared `post_breach_anr_id`
   * (sorted). Answers: "which incidents published a post-breach privacy
   * notice?".
   */
  incidentsWithPostBreachAnr: string[];
  /**
   * Incident ids whose `breach.dpa_notified` event declared `qes_aar_id`
   * (sorted). Answers: "which DPA filings carry an independent QES
   * attestation?".
   */
  incidentsWithQesAttestation: string[];
}

/**
 * Roll up cross-family composition coverage across a corpus of ABR
 * receipts. Auditor surface for "how many of our incidents are
 * compositionally complete?" — does NOT validate that cited receipts
 * resolve (that requires the corresponding cross-family corpus).
 */
export function buildAbrCoverageReport(
  receipts: readonly AbrChainReceipt[],
): AbrCoverageReport {
  const incidentIds = new Set<string>();
  const citedArr = new Set<string>();
  const citedAtr = new Set<string>();
  const citedAer = new Set<string>();
  const citedAnr = new Set<string>();
  const citedAar = new Set<string>();

  const incAer = new Set<string>();
  const incContComp = new Set<string>();
  const incPostAnr = new Set<string>();
  const incQes = new Set<string>();

  for (const r of receipts) {
    incidentIds.add(r.body.incident_correlation_id);
    const links = extractAbrComposition(r.body);

    for (const id of links.containmentRemediationArrIds) citedArr.add(id);
    for (const id of links.transferSuspensionAtrIds) citedAtr.add(id);
    for (const id of links.affectedAerIds) citedAer.add(id);
    if (links.postBreachAnrId !== null) citedAnr.add(links.postBreachAnrId);
    if (links.qesAarId !== null) citedAar.add(links.qesAarId);

    const inc = r.body.incident_correlation_id;
    if (
      r.body.event_type === "breach.detected"
      && links.affectedAerIds.length > 0
    ) {
      incAer.add(inc);
    }
    if (
      r.body.event_type === "breach.contained"
      && (
        links.containmentRemediationArrIds.length > 0
        || links.transferSuspensionAtrIds.length > 0
      )
    ) {
      incContComp.add(inc);
    }
    if (
      r.body.event_type === "breach.closed"
      && links.postBreachAnrId !== null
    ) {
      incPostAnr.add(inc);
    }
    if (
      r.body.event_type === "breach.dpa_notified"
      && links.qesAarId !== null
    ) {
      incQes.add(inc);
    }
  }

  return {
    totalAbrReceipts: receipts.length,
    incidentIds: Array.from(incidentIds).sort(),
    citedArrIds: Array.from(citedArr).sort(),
    citedAtrIds: Array.from(citedAtr).sort(),
    citedAerIds: Array.from(citedAer).sort(),
    citedAnrIds: Array.from(citedAnr).sort(),
    citedAarIds: Array.from(citedAar).sort(),
    incidentsWithAerCoverage: Array.from(incAer).sort(),
    incidentsWithContainmentComposition: Array.from(incContComp).sort(),
    incidentsWithPostBreachAnr: Array.from(incPostAnr).sort(),
    incidentsWithQesAttestation: Array.from(incQes).sort(),
  };
}
