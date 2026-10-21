/**
 * ACR ↔ ANR composition surface (spec §8.1) + optional ALR translation
 * provenance surface (spec §8.3).
 *
 * Distinct from `chain.ts`:
 *   - `chain.ts` walks ANR's own envelope-`prev` chain (intra-family, linear,
 *     with a single translation-branch sidecar).
 *   - `composition.ts` (this module) handles cross-family edges: ACR receipts
 *     pointing inbound via `body.anr_id` (mandatory on v1.2+ ACR issuers) and
 *     `notice.translated` ANR receipts pointing outbound via
 *     `body.translation_provenance_alr_id` (optional, ALR `derived_from`).
 *
 * Both modules are pure: no I/O, no network resolution, no caller-supplied
 * verifier callbacks. Auditors / cross-family tooling build a corpus, hand it
 * in, and receive deterministic roll-ups.
 *
 * The ACR side is intentionally defensive: ACR v1 / v1.1 body types do NOT
 * yet declare `anr_id` (that field lands with ACR v1.2 per spec §8.1's
 * "MAY → MUST" upgrade language). This module accepts a minimal projection
 * (`AcrCompositionReceipt`) so that callers can hand in pre-v1.2 ACR
 * receipts without a type-error and the extractor surfaces them as
 * "no anr_id declared" rather than failing.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/anr §8.
 */

import type { AnrBody, AnrTranslatedBody } from "./types.ts";
import type { AnrChainReceipt } from "./chain.ts";

// ── ACR projection ────────────────────────────────────────────────────────────

/**
 * Minimal ACR receipt shape consumed by the composition module. Callers
 * may hand in either a full `Envelope<AcrBody>` or a thin projection;
 * only `id` and `body.anr_id` are read.
 *
 * Defensive against ACR v1 / v1.1 bodies that do NOT yet carry `anr_id`:
 * the field is typed `string | null | undefined`. Extraction returns
 * `null` for both `undefined` and `null`.
 */
export interface AcrCompositionReceipt {
  /** Envelope ID (ULID). */
  id: string;
  /** ACR body — only `anr_id` is read. Other fields are passed through opaquely. */
  body: {
    anr_id?: string | null;
    [key: string]: unknown;
  };
}

// ── Inbound ACR → ANR extraction ──────────────────────────────────────────────

export interface AcrAnrLink {
  /** The ANR receipt ID this ACR receipt cites, or `null` when absent. */
  anrId: string | null;
}

/**
 * Pull the `anr_id` reference out of an ACR receipt's body. Returns `null`
 * for both v1 / v1.1 receipts (no field) and v1.2+ receipts that explicitly
 * set `anr_id` to `null` (legacy migration window).
 *
 * Pure — no resolution, no validation of the cited ANR receipt's existence.
 */
export function extractAcrAnrLink(acrBody: AcrCompositionReceipt["body"]): AcrAnrLink {
  const raw = acrBody.anr_id;
  if (typeof raw === "string" && raw.length > 0) return { anrId: raw };
  return { anrId: null };
}

// ── Inbound reverse index ─────────────────────────────────────────────────────

/**
 * Map of `anr_receipt_id → ACR receipts that cite it via `body.anr_id`.
 * Values are arrays (one ANR receipt may be cited by many ACR receipts).
 * Order within each bucket matches caller input order, deduplicated by ACR
 * envelope `id` so the same ACR receipt appears at most once per bucket.
 */
export type AcrReverseIndex = ReadonlyMap<string, readonly AcrCompositionReceipt[]>;

/**
 * Build a reverse index keyed on ANR receipt ID. ACR receipts with no
 * `anr_id` (or `anr_id: null`) are omitted from the index entirely.
 */
export function buildAcrReverseIndex(
  acrReceipts: readonly AcrCompositionReceipt[],
): AcrReverseIndex {
  const out = new Map<string, AcrCompositionReceipt[]>();
  for (const r of acrReceipts) {
    const { anrId } = extractAcrAnrLink(r.body);
    if (anrId === null) continue;
    const bucket = out.get(anrId);
    if (bucket === undefined) {
      out.set(anrId, [r]);
      continue;
    }
    if (bucket.every((existing) => existing.id !== r.id)) bucket.push(r);
  }
  return out;
}

// ── Coverage roll-up ──────────────────────────────────────────────────────────

export interface NoticeCoverageReport {
  /** Total ACR receipts in the input corpus. */
  totalAcrReceipts: number;
  /** ACR receipts that declare a non-null `anr_id`. */
  acrWithAnrCitation: number;
  /** ACR receipts whose `anr_id` does NOT resolve to any ANR in the supplied corpus. */
  acrWithUnresolvableAnrId: number;
  /** Distinct ANR receipt IDs cited across the ACR corpus, sorted lexicographically. */
  citedAnrIds: string[];
  /** ANR receipts in the input corpus that are cited by ≥1 ACR receipt. */
  citedAnrReceipts: AnrChainReceipt[];
  /** ANR receipts in the input corpus that are NOT cited by any ACR receipt. */
  uncitedAnrReceipts: AnrChainReceipt[];
}

/**
 * Roll up ACR-coverage statistics across a corpus. Answers auditor questions
 * like "what fraction of consent receipts cite a notice receipt?" and
 * "which notices have no consent attached?".
 *
 * `acrWithUnresolvableAnrId` flags ACR receipts whose `anr_id` is not in the
 * supplied ANR corpus — typically because the auditor was given a partial
 * snapshot, OR because the ACR issuer is referencing a notice from a sibling
 * controller. Composition does NOT fail-hard on unresolvable refs; that is
 * the ACR verifier's job per spec §8.1.
 */
export function buildNoticeCoverageReport(
  anrReceipts: readonly AnrChainReceipt[],
  acrReceipts: readonly AcrCompositionReceipt[],
): NoticeCoverageReport {
  const reverseIndex = buildAcrReverseIndex(acrReceipts);
  const anrById = new Map<string, AnrChainReceipt>();
  for (const a of anrReceipts) {
    if (!anrById.has(a.id)) anrById.set(a.id, a);
  }

  let acrWithAnrCitation = 0;
  let acrWithUnresolvableAnrId = 0;
  for (const r of acrReceipts) {
    const { anrId } = extractAcrAnrLink(r.body);
    if (anrId === null) continue;
    acrWithAnrCitation += 1;
    if (!anrById.has(anrId)) acrWithUnresolvableAnrId += 1;
  }

  const citedAnrReceipts: AnrChainReceipt[] = [];
  const uncitedAnrReceipts: AnrChainReceipt[] = [];
  for (const a of anrReceipts) {
    if (reverseIndex.has(a.id)) citedAnrReceipts.push(a);
    else uncitedAnrReceipts.push(a);
  }

  const citedAnrIds = Array.from(reverseIndex.keys()).sort();

  return {
    totalAcrReceipts: acrReceipts.length,
    acrWithAnrCitation,
    acrWithUnresolvableAnrId,
    citedAnrIds,
    citedAnrReceipts,
    uncitedAnrReceipts,
  };
}

// ── Outbound ANR → ALR (translation provenance, §8.3) ─────────────────────────

export interface AlrTranslationProvenanceLink {
  /** The ALR `derived_from` receipt ID this `notice.translated` cites, or `null`. */
  alrId: string | null;
}

/**
 * Pull the `translation_provenance_alr_id` reference out of a
 * `notice.translated` ANR body. Returns `{ alrId: null }` for any other
 * event type (the field does not exist) and for translation bodies that
 * explicitly set it `null`.
 *
 * Pure — does NOT resolve the cited ALR receipt or verify the
 * `artifact_hash` ↔ `policy_hash` match described in spec §8.3 (that
 * cross-check belongs to a future ANR↔ALR cross-verifier pass).
 */
export function extractAlrTranslationProvenance(
  anrBody: AnrBody,
): AlrTranslationProvenanceLink {
  if (anrBody.event_type !== "notice.translated") return { alrId: null };
  const tBody = anrBody as AnrTranslatedBody;
  const raw = tBody.translation_provenance_alr_id;
  if (typeof raw === "string" && raw.length > 0) return { alrId: raw };
  return { alrId: null };
}

/**
 * Map of `alr_receipt_id → ANR `notice.translated` receipts that cite it via
 * `body.translation_provenance_alr_id`. Values are arrays (one ALR receipt
 * may be cited by multiple translations into different languages).
 */
export type AlrTranslationProvenanceIndex = ReadonlyMap<
  string,
  readonly AnrChainReceipt[]
>;

export function buildAlrTranslationProvenanceIndex(
  anrReceipts: readonly AnrChainReceipt[],
): AlrTranslationProvenanceIndex {
  const out = new Map<string, AnrChainReceipt[]>();
  for (const r of anrReceipts) {
    const { alrId } = extractAlrTranslationProvenance(r.body);
    if (alrId === null) continue;
    const bucket = out.get(alrId);
    if (bucket === undefined) {
      out.set(alrId, [r]);
      continue;
    }
    if (bucket.every((existing) => existing.id !== r.id)) bucket.push(r);
  }
  return out;
}
