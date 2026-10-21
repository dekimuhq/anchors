/**
 * Composition tests for @dekimuhq/asr — spec §8 cross-family auditor surface.
 *
 * Pure-function module: no envelope minting needed. Tests build minimal receipt
 * projections directly and assert the deterministic roll-ups. Complements
 * `compose.test.ts` (which tests the verify-time resolver callback).
 *
 * Coverage:
 *   E1  — extractAsrComposition: arr_receipt_id present → arrId set.
 *   E2  — extractAsrComposition: recipient_set_alr_ids → sorted, deduped.
 *   E3  — extractAsrComposition: apur_receipt_id + atr_receipt_id (cast fields).
 *   E4  — extractAsrComposition: no edges (request.received) → all empty.
 *   E5  — extractAsrComposition: empty-string ref → null.
 *   E6  — extractAsrComposition: non-string ALR entries filtered out.
 *
 *   A1  — buildArrReverseIndex: empty corpus → empty map.
 *   A2  — buildArrReverseIndex: 3 ASRs, 2 unique ARR ids → 2 buckets.
 *   A3  — buildArrReverseIndex: same ASR id cited twice → deduped within bucket.
 *   A4  — buildArrReverseIndex: receipt without arr_receipt_id skipped.
 *
 *   L1  — buildAlrRecipientReverseIndex: one notify with 2 ALR ids → 2 buckets.
 *   L2  — buildAlrRecipientReverseIndex: two notifies share an ALR id → bucket of 2.
 *
 *   P1  — buildApurReverseIndex: indexes apur_receipt_id.
 *   T1  — buildAtrReverseIndex: indexes atr_receipt_id.
 *
 *   S1  — buildArt17SatisfactionReport: empty corpora → zeros.
 *   S2  — buildArt17SatisfactionReport: satisfied vs unresolvable split.
 *   S3  — buildArt17SatisfactionReport: citedArrIds sorted lexicographically.
 *   S4  — buildArt17SatisfactionReport: non-erasure receipts ignored.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AsrBody } from "../src/types.ts";
import {
  bodyFulfilled,
  bodyRecipientNotified,
  bodyRequestReceived,
} from "./_helpers/fixtures.ts";
import {
  extractAsrComposition,
  buildArrReverseIndex,
  buildAlrRecipientReverseIndex,
  buildApurReverseIndex,
  buildAtrReverseIndex,
  buildArt17SatisfactionReport,
  type AsrCompositionReceipt,
} from "../src/composition.ts";

// ── Fixture builders ──────────────────────────────────────────────────────────

/** Erasure fulfilment carrying an `arr_receipt_id` (§8.1). */
function fulfilledWithArr(arrId: string): AsrBody {
  return { ...bodyFulfilled(), arr_receipt_id: arrId } as AsrBody;
}

/** Recipient-notified body with an explicit ALR set (§8.4). */
function notifyWithAlr(alrIds: readonly string[]): AsrBody {
  return { ...bodyRecipientNotified(), recipient_set_alr_ids: alrIds } as AsrBody;
}

function receipt(id: string, body: AsrBody): AsrCompositionReceipt {
  return { id, body };
}

// ── E1–E6: extractAsrComposition ─────────────────────────────────────────────

test("composition E1: extractAsrComposition surfaces arr_receipt_id", () => {
  const refs = extractAsrComposition(fulfilledWithArr("arr_01"));
  assert.equal(refs.arrId, "arr_01");
  assert.equal(refs.apurId, null);
  assert.equal(refs.atrId, null);
  assert.deepEqual(refs.alrRecipientIds, []);
});

test("composition E2: recipient_set_alr_ids sorted and deduped", () => {
  const refs = extractAsrComposition(notifyWithAlr(["alr_c", "alr_a", "alr_c", "alr_b"]));
  assert.deepEqual(refs.alrRecipientIds, ["alr_a", "alr_b", "alr_c"]);
});

test("composition E3: apur_receipt_id + atr_receipt_id (cast fields) extracted", () => {
  const body = {
    ...bodyFulfilled(),
    apur_receipt_id: "apur_9",
    atr_receipt_id: "atr_9",
  } as AsrBody;
  const refs = extractAsrComposition(body);
  assert.equal(refs.apurId, "apur_9");
  assert.equal(refs.atrId, "atr_9");
});

test("composition E4: body with no cross-family edges → all empty", () => {
  const refs = extractAsrComposition(bodyRequestReceived());
  assert.equal(refs.arrId, null);
  assert.equal(refs.apurId, null);
  assert.equal(refs.atrId, null);
  assert.deepEqual(refs.alrRecipientIds, []);
});

test("composition E5: empty-string ref → null", () => {
  const refs = extractAsrComposition(fulfilledWithArr(""));
  assert.equal(refs.arrId, null);
});

test("composition E6: non-string ALR entries filtered out", () => {
  const body = {
    ...bodyRecipientNotified(),
    recipient_set_alr_ids: ["alr_ok", 42, null, "", "alr_ok2"],
  } as unknown as AsrBody;
  const refs = extractAsrComposition(body);
  assert.deepEqual(refs.alrRecipientIds, ["alr_ok", "alr_ok2"]);
});

// ── A1–A4: buildArrReverseIndex ──────────────────────────────────────────────

test("composition A1: buildArrReverseIndex empty corpus → empty map", () => {
  assert.equal(buildArrReverseIndex([]).size, 0);
});

test("composition A2: 3 ASRs, 2 unique ARR ids → 2 buckets", () => {
  const idx = buildArrReverseIndex([
    receipt("asr_1", fulfilledWithArr("arr_a")),
    receipt("asr_2", fulfilledWithArr("arr_b")),
    receipt("asr_3", fulfilledWithArr("arr_a")),
  ]);
  assert.equal(idx.size, 2);
  assert.deepEqual(
    (idx.get("arr_a") ?? []).map((r) => r.id),
    ["asr_1", "asr_3"],
  );
  assert.deepEqual(
    (idx.get("arr_b") ?? []).map((r) => r.id),
    ["asr_2"],
  );
});

test("composition A3: same ASR id never duplicated within a bucket", () => {
  const r = receipt("asr_dup", fulfilledWithArr("arr_a"));
  const idx = buildArrReverseIndex([r, r]);
  assert.deepEqual((idx.get("arr_a") ?? []).map((x) => x.id), ["asr_dup"]);
});

test("composition A4: receipt without arr_receipt_id skipped", () => {
  const idx = buildArrReverseIndex([
    receipt("asr_1", bodyRequestReceived()),
    receipt("asr_2", fulfilledWithArr("arr_a")),
  ]);
  assert.equal(idx.size, 1);
  assert.ok(idx.has("arr_a"));
});

// ── L1–L2: buildAlrRecipientReverseIndex ─────────────────────────────────────

test("composition L1: one notify with 2 ALR ids → 2 buckets", () => {
  const idx = buildAlrRecipientReverseIndex([
    receipt("asr_n", notifyWithAlr(["alr_1", "alr_2"])),
  ]);
  assert.equal(idx.size, 2);
  assert.deepEqual((idx.get("alr_1") ?? []).map((r) => r.id), ["asr_n"]);
  assert.deepEqual((idx.get("alr_2") ?? []).map((r) => r.id), ["asr_n"]);
});

test("composition L2: two notifies sharing an ALR id → bucket of 2", () => {
  const idx = buildAlrRecipientReverseIndex([
    receipt("asr_a", notifyWithAlr(["alr_shared"])),
    receipt("asr_b", notifyWithAlr(["alr_shared", "alr_other"])),
  ]);
  assert.deepEqual((idx.get("alr_shared") ?? []).map((r) => r.id), ["asr_a", "asr_b"]);
  assert.deepEqual((idx.get("alr_other") ?? []).map((r) => r.id), ["asr_b"]);
});

// ── P1 / T1: APuR + ATR reverse indices ──────────────────────────────────────

test("composition P1: buildApurReverseIndex indexes apur_receipt_id", () => {
  const body = { ...bodyFulfilled(), apur_receipt_id: "apur_1" } as AsrBody;
  const idx = buildApurReverseIndex([receipt("asr_1", body)]);
  assert.deepEqual((idx.get("apur_1") ?? []).map((r) => r.id), ["asr_1"]);
});

test("composition T1: buildAtrReverseIndex indexes atr_receipt_id", () => {
  const body = { ...bodyFulfilled(), atr_receipt_id: "atr_1" } as AsrBody;
  const idx = buildAtrReverseIndex([receipt("asr_1", body)]);
  assert.deepEqual((idx.get("atr_1") ?? []).map((r) => r.id), ["asr_1"]);
});

// ── S1–S4: buildArt17SatisfactionReport ──────────────────────────────────────

test("composition S1: empty corpora → zeros", () => {
  const rep = buildArt17SatisfactionReport([], []);
  assert.deepEqual(rep, {
    totalAsrReceipts: 0,
    erasureFulfilments: 0,
    satisfiedFulfilments: 0,
    unresolvableFulfilments: 0,
    citedArrIds: [],
    satisfiedReceipts: [],
    unresolvableReceipts: [],
  });
});

test("composition S2: satisfied vs unresolvable split", () => {
  const rep = buildArt17SatisfactionReport(
    [
      receipt("asr_1", fulfilledWithArr("arr_present")),
      receipt("asr_2", fulfilledWithArr("arr_missing")),
      receipt("asr_3", bodyRequestReceived()),
    ],
    [{ id: "arr_present" }],
  );
  assert.equal(rep.totalAsrReceipts, 3);
  assert.equal(rep.erasureFulfilments, 2);
  assert.equal(rep.satisfiedFulfilments, 1);
  assert.equal(rep.unresolvableFulfilments, 1);
  assert.deepEqual(rep.satisfiedReceipts.map((r) => r.id), ["asr_1"]);
  assert.deepEqual(rep.unresolvableReceipts.map((r) => r.id), ["asr_2"]);
});

test("composition S3: citedArrIds sorted lexicographically", () => {
  const rep = buildArt17SatisfactionReport(
    [
      receipt("asr_1", fulfilledWithArr("arr_c")),
      receipt("asr_2", fulfilledWithArr("arr_a")),
      receipt("asr_3", fulfilledWithArr("arr_b")),
    ],
    [],
  );
  assert.deepEqual(rep.citedArrIds, ["arr_a", "arr_b", "arr_c"]);
});

test("composition S4: non-erasure receipts ignored in the roll-up", () => {
  const rep = buildArt17SatisfactionReport(
    [
      receipt("asr_1", bodyRequestReceived()),
      receipt("asr_2", notifyWithAlr(["alr_1"])),
    ],
    [{ id: "arr_x" }],
  );
  assert.equal(rep.erasureFulfilments, 0);
  assert.deepEqual(rep.citedArrIds, []);
});
