/**
 * Composition tests for @dekimuhq/anr-verifier — Phase 2 §G.
 *
 * Spec §8.1 (ACR → ANR mandatory) + §8.3 (ALR ← ANR translation provenance).
 *
 * Pure-function module: no envelope minting needed. Tests build minimal
 * receipt projections directly and assert the deterministic roll-ups.
 *
 * Coverage:
 *   E1 — extractAcrAnrLink: returns anr_id when present.
 *   E2 — extractAcrAnrLink: returns null when field missing (pre-v1.2 ACR).
 *   E3 — extractAcrAnrLink: returns null when explicit null.
 *   E4 — extractAcrAnrLink: returns null for empty string.
 *   E5 — extractAcrAnrLink: returns null for non-string value.
 *
 *   R1 — buildAcrReverseIndex: empty corpus → empty map.
 *   R2 — buildAcrReverseIndex: 3 ACRs, 2 unique anr_ids → 2 buckets.
 *   R3 — buildAcrReverseIndex: same ACR id cited twice → deduped within bucket.
 *   R4 — buildAcrReverseIndex: ACR without anr_id skipped.
 *   R5 — buildAcrReverseIndex: bucket order matches input order.
 *
 *   N1 — buildNoticeCoverageReport: empty corpora → zeros.
 *   N2 — buildNoticeCoverageReport: full split — cited vs uncited ANRs.
 *   N3 — buildNoticeCoverageReport: counts unresolvable anr_ids.
 *   N4 — buildNoticeCoverageReport: citedAnrIds sorted lexicographically.
 *   N5 — buildNoticeCoverageReport: duplicate ANR ids in input keep first.
 *
 *   T1 — extractAlrTranslationProvenance: translation + non-null → returns it.
 *   T2 — extractAlrTranslationProvenance: translation + null → null.
 *   T3 — extractAlrTranslationProvenance: non-translation event → null.
 *
 *   I1 — buildAlrTranslationProvenanceIndex: empty corpus → empty map.
 *   I2 — buildAlrTranslationProvenanceIndex: 3 translations, 2 unique ALR ids
 *        → 2 buckets, dedupe by ANR receipt id.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AnrBody, AnrTranslatedBody, AnrPresentedBody } from "../src/types.ts";
import type { AnrChainReceipt } from "../src/chain.ts";
import {
  extractAcrAnrLink,
  buildAcrReverseIndex,
  buildNoticeCoverageReport,
  extractAlrTranslationProvenance,
  buildAlrTranslationProvenanceIndex,
  type AcrCompositionReceipt,
} from "../src/composition.ts";

// ── Fixture builders ──────────────────────────────────────────────────────────

function acr(id: string, anr_id: string | null | undefined): AcrCompositionReceipt {
  const body: AcrCompositionReceipt["body"] =
    anr_id === undefined ? {} : { anr_id };
  return { id, body };
}

function presentedBody(): AnrPresentedBody {
  return {
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/notice/v1",
    rights_surface: ["art15"],
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    base_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
  };
}

function translatedBody(
  base_anr_id: string,
  translation_provenance_alr_id: string | null,
): AnrTranslatedBody {
  return {
    profile: "notice.art13.collected_direct",
    lang_tag: "es-ES",
    lang_inferred: null,
    qts_attestation_hash: null,
    event_type: "notice.translated",
    base_anr_id,
    jurisdiction: null,
    translation_provenance_alr_id,
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
  };
}

function anr(id: string, body: AnrBody): AnrChainReceipt {
  return {
    id,
    iss: "did:web:controller.test",
    policy_uri: "https://controller.test/notice/v1",
    prev: null,
    body,
  };
}

// ── E1–E5: extractAcrAnrLink ─────────────────────────────────────────────────

test("composition E1: extractAcrAnrLink returns anr_id when present", () => {
  const link = extractAcrAnrLink({ anr_id: "01HABCNOTICE" });
  assert.equal(link.anrId, "01HABCNOTICE");
});

test("composition E2: extractAcrAnrLink returns null when field missing (pre-v1.2 ACR)", () => {
  const link = extractAcrAnrLink({});
  assert.equal(link.anrId, null);
});

test("composition E3: extractAcrAnrLink returns null when explicit null", () => {
  const link = extractAcrAnrLink({ anr_id: null });
  assert.equal(link.anrId, null);
});

test("composition E4: extractAcrAnrLink returns null for empty string", () => {
  const link = extractAcrAnrLink({ anr_id: "" });
  assert.equal(link.anrId, null);
});

test("composition E5: extractAcrAnrLink returns null for non-string value", () => {
  // Defensive against corrupted input. Cast bridges the type test boundary.
  const link = extractAcrAnrLink({ anr_id: 42 as unknown as string });
  assert.equal(link.anrId, null);
});

// ── R1–R5: buildAcrReverseIndex ──────────────────────────────────────────────

test("composition R1: buildAcrReverseIndex on empty corpus → empty map", () => {
  const idx = buildAcrReverseIndex([]);
  assert.equal(idx.size, 0);
});

test("composition R2: buildAcrReverseIndex with 3 ACRs and 2 anr_ids → 2 buckets", () => {
  const a = acr("acr-1", "anr-A");
  const b = acr("acr-2", "anr-B");
  const c = acr("acr-3", "anr-A");
  const idx = buildAcrReverseIndex([a, b, c]);
  assert.equal(idx.size, 2);
  assert.deepEqual(
    idx.get("anr-A")?.map((r) => r.id),
    ["acr-1", "acr-3"],
  );
  assert.deepEqual(
    idx.get("anr-B")?.map((r) => r.id),
    ["acr-2"],
  );
});

test("composition R3: buildAcrReverseIndex dedupes same ACR id within a bucket", () => {
  const a = acr("acr-1", "anr-A");
  const aDup = acr("acr-1", "anr-A");
  const idx = buildAcrReverseIndex([a, aDup]);
  assert.equal(idx.size, 1);
  assert.equal(idx.get("anr-A")?.length, 1);
});

test("composition R4: buildAcrReverseIndex skips ACRs without anr_id", () => {
  const cited = acr("acr-1", "anr-A");
  const naked = acr("acr-2", undefined);
  const nulled = acr("acr-3", null);
  const idx = buildAcrReverseIndex([cited, naked, nulled]);
  assert.equal(idx.size, 1);
  assert.deepEqual(
    idx.get("anr-A")?.map((r) => r.id),
    ["acr-1"],
  );
});

test("composition R5: buildAcrReverseIndex preserves input order within buckets", () => {
  const inputs: AcrCompositionReceipt[] = [
    acr("acr-z", "anr-A"),
    acr("acr-a", "anr-A"),
    acr("acr-m", "anr-A"),
  ];
  const idx = buildAcrReverseIndex(inputs);
  assert.deepEqual(
    idx.get("anr-A")?.map((r) => r.id),
    ["acr-z", "acr-a", "acr-m"],
  );
});

// ── N1–N5: buildNoticeCoverageReport ─────────────────────────────────────────

test("composition N1: buildNoticeCoverageReport on empty corpora → zeros", () => {
  const r = buildNoticeCoverageReport([], []);
  assert.equal(r.totalAcrReceipts, 0);
  assert.equal(r.acrWithAnrCitation, 0);
  assert.equal(r.acrWithUnresolvableAnrId, 0);
  assert.deepEqual(r.citedAnrIds, []);
  assert.deepEqual(r.citedAnrReceipts, []);
  assert.deepEqual(r.uncitedAnrReceipts, []);
});

test("composition N2: buildNoticeCoverageReport splits cited vs uncited ANRs", () => {
  const anr1 = anr("anr-1", presentedBody());
  const anr2 = anr("anr-2", presentedBody());
  const acrs: AcrCompositionReceipt[] = [
    acr("acr-1", "anr-1"),
    acr("acr-2", "anr-1"),
    acr("acr-3", null),
    acr("acr-4", undefined),
  ];
  const r = buildNoticeCoverageReport([anr1, anr2], acrs);
  assert.equal(r.totalAcrReceipts, 4);
  assert.equal(r.acrWithAnrCitation, 2);
  assert.equal(r.acrWithUnresolvableAnrId, 0);
  assert.deepEqual(r.citedAnrIds, ["anr-1"]);
  assert.deepEqual(
    r.citedAnrReceipts.map((a) => a.id),
    ["anr-1"],
  );
  assert.deepEqual(
    r.uncitedAnrReceipts.map((a) => a.id),
    ["anr-2"],
  );
});

test("composition N3: buildNoticeCoverageReport counts unresolvable anr_ids", () => {
  const anr1 = anr("anr-1", presentedBody());
  const acrs: AcrCompositionReceipt[] = [
    acr("acr-1", "anr-1"),
    acr("acr-2", "anr-unknown-A"),
    acr("acr-3", "anr-unknown-B"),
    acr("acr-4", "anr-unknown-A"),
  ];
  const r = buildNoticeCoverageReport([anr1], acrs);
  assert.equal(r.acrWithAnrCitation, 4);
  assert.equal(r.acrWithUnresolvableAnrId, 3);
});

test("composition N4: buildNoticeCoverageReport sorts citedAnrIds lexicographically", () => {
  const acrs: AcrCompositionReceipt[] = [
    acr("acr-1", "anr-zulu"),
    acr("acr-2", "anr-alpha"),
    acr("acr-3", "anr-mike"),
  ];
  const r = buildNoticeCoverageReport([], acrs);
  assert.deepEqual(r.citedAnrIds, ["anr-alpha", "anr-mike", "anr-zulu"]);
});

test("composition N5: buildNoticeCoverageReport dedupes ANR input by id (keeps first)", () => {
  const anrFirst = anr("anr-1", presentedBody());
  const anrDup: AnrChainReceipt = {
    ...anr("anr-1", presentedBody()),
    iss: "did:web:other.test",
  };
  const r = buildNoticeCoverageReport([anrFirst, anrDup], [acr("acr-1", "anr-1")]);
  assert.equal(r.citedAnrReceipts.length, 2);
  // No unresolvable refs — both entries resolve to the same id.
  assert.equal(r.acrWithUnresolvableAnrId, 0);
});

// ── T1–T3: extractAlrTranslationProvenance ───────────────────────────────────

test("composition T1: extractAlrTranslationProvenance returns alrId on translated body", () => {
  const body = translatedBody("anr-base", "alr-prov-1");
  const link = extractAlrTranslationProvenance(body);
  assert.equal(link.alrId, "alr-prov-1");
});

test("composition T2: extractAlrTranslationProvenance returns null when field null", () => {
  const body = translatedBody("anr-base", null);
  const link = extractAlrTranslationProvenance(body);
  assert.equal(link.alrId, null);
});

test("composition T3: extractAlrTranslationProvenance returns null for non-translation event", () => {
  const link = extractAlrTranslationProvenance(presentedBody());
  assert.equal(link.alrId, null);
});

// ── I1–I2: buildAlrTranslationProvenanceIndex ────────────────────────────────

test("composition I1: buildAlrTranslationProvenanceIndex on empty corpus → empty map", () => {
  const idx = buildAlrTranslationProvenanceIndex([]);
  assert.equal(idx.size, 0);
});

test("composition I2: buildAlrTranslationProvenanceIndex groups 3 translations across 2 ALR ids", () => {
  const t1 = anr("anr-t1", translatedBody("anr-base", "alr-1"));
  const t2 = anr("anr-t2", translatedBody("anr-base", "alr-2"));
  const t3 = anr("anr-t3", translatedBody("anr-base", "alr-1"));
  const nonTrans = anr("anr-p", presentedBody());
  const idx = buildAlrTranslationProvenanceIndex([t1, t2, t3, nonTrans]);
  assert.equal(idx.size, 2);
  assert.deepEqual(
    idx.get("alr-1")?.map((r) => r.id),
    ["anr-t1", "anr-t3"],
  );
  assert.deepEqual(
    idx.get("alr-2")?.map((r) => r.id),
    ["anr-t2"],
  );
});
