/**
 * ASR cross-family composition surface (spec §8) — pure offline auditor module.
 *
 * Distinct from `compose.ts`:
 *   - `compose.ts` is the VERIFY-time `ComposeCallback` wired into the family
 *     manifest. It resolves cited receipts through caller-supplied resolvers
 *     (`resolveArr` / `resolveAlr` / `resolveAtr` / `resolveApur`), fails
 *     closed on a broken cross-walk, and emits informational warnings. It runs
 *     on ONE receipt at a time, inside the verifier.
 *   - `composition.ts` (this module) is the auditor surface: it takes a corpus
 *     of already-verified ASR receipts, extracts their cross-family reference
 *     edges, and returns deterministic reverse-indices + roll-ups. No I/O, no
 *     resolvers, no callbacks — answers "which ARR does this erasure request
 *     cite?", "which receipts reference this ALR recipient set?", "are all my
 *     Art. 17 erasure requests backed by an anchored deletion receipt?".
 *
 * Both modules are intentionally complementary. The verifier uses `compose.ts`;
 * compliance tooling (Compass) and auditors use this module.
 *
 * The four edges (spec §8):
 *   §8.1  ARR  — `body.arr_receipt_id`        (MANDATORY on art17.erasure_request fulfilled)
 *   §8.2  APuR — `body.apur_receipt_id`       (OPTIONAL  on art21.objection fulfilled)
 *   §8.3  ATR  — `body.atr_receipt_id`        (OPTIONAL  on art20.portability fulfilled, cross-border)
 *   §8.4  ALR  — `body.recipient_set_alr_ids` (MANDATORY shape on request.recipient_notified)
 *
 * Field-shape note: `arr_receipt_id` and `recipient_set_alr_ids` are declared
 * on the shipped `AsrBody` union; `apur_receipt_id` and `atr_receipt_id` are
 * profile-level fields that the body union does not yet declare (they ride the
 * envelope at runtime and are read by `compose.ts` via cast). This module reads
 * all four via narrow casts so it indexes whatever refs a receipt actually
 * carries, independent of which profile/event produced it — exactly what an
 * offline auditor needs.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/asr §8.
 */

import type { AsrBody } from "./types.ts";

// ── Receipt projection ──────────────────────────────────────────────────────────

/**
 * Minimal ASR receipt shape consumed by this module. Callers may hand in a
 * full `Envelope<AsrBody>` or a thin projection; only `id` and `body` are read.
 */
export interface AsrCompositionReceipt {
  /** Envelope ID (ULID). */
  id: string;
  /** ASR body — the discriminated union over the 9 event types. */
  body: AsrBody;
}

/**
 * Minimal foreign-receipt projection for resolution checks in the coverage
 * roll-ups. Only `id` is read; callers may hand in full envelopes of any
 * family (ARR/ALR/…) or thin `{ id }` projections.
 */
export interface ForeignReceiptRef {
  /** Envelope ID (ULID) of the referenced receipt. */
  id: string;
}

// ── Per-body extraction ─────────────────────────────────────────────────────────

/**
 * The cross-family reference edges carried by a single ASR body. Each scalar
 * field is `null` when the corresponding ref is absent, empty, or non-string;
 * `alrRecipientIds` is the deduplicated, lexicographically-sorted set of ALR
 * recipient ids (empty when the receipt carries no recipient set).
 */
export interface AsrCompositionRefs {
  /** §8.1 — ARR execution receipt cited by an art17 erasure fulfilment. */
  arrId: string | null;
  /** §8.2 — APuR unbinding receipt back-referenced by an art21 objection fulfilment. */
  apurId: string | null;
  /** §8.3 — ATR transfer receipt paired with an art20 cross-border portability fulfilment. */
  atrId: string | null;
  /** §8.4 — ALR `disclosed` receipt ids forming the Art. 19 recipient set. */
  alrRecipientIds: string[];
}

/** Reads a scalar receipt-id ref from a body field; `null` unless a non-empty string. */
function readScalarRef(body: AsrBody, key: string): string | null {
  const raw = (body as unknown as Record<string, unknown>)[key];
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

/**
 * Decompose an ASR body into its cross-family reference edges. Pure — no
 * resolution, no validation that the cited receipts exist or match. A receipt
 * that carries none of the four edges (e.g. `request.received`,
 * `request.identity_verified`) comes back all-empty.
 */
export function extractAsrComposition(body: AsrBody): AsrCompositionRefs {
  const rawAlrIds = (body as { recipient_set_alr_ids?: unknown }).recipient_set_alr_ids;
  const alrSet = new Set<string>();
  if (Array.isArray(rawAlrIds)) {
    for (const id of rawAlrIds) {
      if (typeof id === "string" && id.length > 0) alrSet.add(id);
    }
  }

  return {
    arrId: readScalarRef(body, "arr_receipt_id"),
    apurId: readScalarRef(body, "apur_receipt_id"),
    atrId: readScalarRef(body, "atr_receipt_id"),
    alrRecipientIds: Array.from(alrSet).sort(),
  };
}

// ── Cross-receipt reverse indices ───────────────────────────────────────────────

/**
 * Map of `foreign_receipt_id → ASR receipts that cite it`. Values are arrays
 * (one foreign receipt may be cited by many ASR receipts). Order within each
 * bucket matches caller input order, deduplicated by ASR envelope `id` so the
 * same ASR receipt appears at most once per bucket.
 */
export type AsrReverseIndex = ReadonlyMap<string, readonly AsrCompositionReceipt[]>;

/** Generic reverse-index builder over a per-receipt ref selector. */
function buildReverseIndex(
  receipts: readonly AsrCompositionReceipt[],
  select: (refs: AsrCompositionRefs) => readonly string[],
): AsrReverseIndex {
  const out = new Map<string, AsrCompositionReceipt[]>();
  for (const r of receipts) {
    for (const refId of select(extractAsrComposition(r.body))) {
      const bucket = out.get(refId);
      if (bucket === undefined) {
        out.set(refId, [r]);
        continue;
      }
      if (bucket.every((existing) => existing.id !== r.id)) bucket.push(r);
    }
  }
  return out;
}

const asArray = (id: string | null): readonly string[] => (id === null ? [] : [id]);

/** Reverse index keyed on ARR receipt id (§8.1 Art. 17 erasure execution). */
export function buildArrReverseIndex(
  receipts: readonly AsrCompositionReceipt[],
): AsrReverseIndex {
  return buildReverseIndex(receipts, (refs) => asArray(refs.arrId));
}

/** Reverse index keyed on ALR receipt id (§8.4 Art. 19 recipient cascade). */
export function buildAlrRecipientReverseIndex(
  receipts: readonly AsrCompositionReceipt[],
): AsrReverseIndex {
  return buildReverseIndex(receipts, (refs) => refs.alrRecipientIds);
}

/** Reverse index keyed on APuR receipt id (§8.2 Art. 21 objection → unbinding). */
export function buildApurReverseIndex(
  receipts: readonly AsrCompositionReceipt[],
): AsrReverseIndex {
  return buildReverseIndex(receipts, (refs) => asArray(refs.apurId));
}

/** Reverse index keyed on ATR receipt id (§8.3 Art. 20 cross-border portability). */
export function buildAtrReverseIndex(
  receipts: readonly AsrCompositionReceipt[],
): AsrReverseIndex {
  return buildReverseIndex(receipts, (refs) => asArray(refs.atrId));
}

// ── Art. 17 satisfaction roll-up ────────────────────────────────────────────────

export interface Art17SatisfactionReport {
  /** Total ASR receipts in the input corpus. */
  totalAsrReceipts: number;
  /** ASR receipts carrying a non-empty `arr_receipt_id` (erasure fulfilments). */
  erasureFulfilments: number;
  /** Erasure fulfilments whose `arr_receipt_id` resolves to a receipt in the supplied ARR corpus. */
  satisfiedFulfilments: number;
  /** Erasure fulfilments whose `arr_receipt_id` does NOT resolve in the supplied ARR corpus. */
  unresolvableFulfilments: number;
  /** Distinct ARR receipt ids cited across the corpus, sorted lexicographically. */
  citedArrIds: string[];
  /** ASR receipts whose cited ARR resolves — the complete Art. 17 evidence bundles. */
  satisfiedReceipts: AsrCompositionReceipt[];
  /** ASR receipts whose cited ARR is absent from the supplied corpus — broken bundles. */
  unresolvableReceipts: AsrCompositionReceipt[];
}

/**
 * Roll up Art. 17 "request → anchored deletion" satisfaction across a corpus.
 * Answers the headline compliance question: "is every erasure request I
 * fulfilled backed by an anchored ARR deletion receipt?" — the Art. 17 +
 * Art. 12(3) "honoured-within-30-days" evidence bundle (spec §8.1).
 *
 * `unresolvableReceipts` flags erasure fulfilments whose `arr_receipt_id` is
 * not in the supplied ARR corpus — typically a partial snapshot or a dangling
 * reference. This module does NOT fail-hard on unresolvable refs or check
 * subject parity / the ±14-day window; that is the verifier's job
 * (`compose.ts`, spec §5.3). Here we surface completeness, not validity.
 */
export function buildArt17SatisfactionReport(
  asrReceipts: readonly AsrCompositionReceipt[],
  arrReceipts: readonly ForeignReceiptRef[],
): Art17SatisfactionReport {
  const arrIds = new Set<string>();
  for (const a of arrReceipts) arrIds.add(a.id);

  const citedArrIds = new Set<string>();
  const satisfiedReceipts: AsrCompositionReceipt[] = [];
  const unresolvableReceipts: AsrCompositionReceipt[] = [];

  for (const r of asrReceipts) {
    const { arrId } = extractAsrComposition(r.body);
    if (arrId === null) continue;
    citedArrIds.add(arrId);
    if (arrIds.has(arrId)) satisfiedReceipts.push(r);
    else unresolvableReceipts.push(r);
  }

  return {
    totalAsrReceipts: asrReceipts.length,
    erasureFulfilments: satisfiedReceipts.length + unresolvableReceipts.length,
    satisfiedFulfilments: satisfiedReceipts.length,
    unresolvableFulfilments: unresolvableReceipts.length,
    citedArrIds: Array.from(citedArrIds).sort(),
    satisfiedReceipts,
    unresolvableReceipts,
  };
}
