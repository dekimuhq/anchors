/**
 * Tests for the cross-family composition surface (spec §8 + audit-fix C5).
 *
 * Builds in-memory `AbrChainReceipt` projections covering each of the five
 * mandatory composition fields:
 *
 *   - `breach.detected.affected_aer_ids`        → AER (`ar.evaluation.v1`)
 *   - `breach.contained.containment_remediation_arr_ids` → ARR
 *   - `breach.contained.transfer_suspension_atr_ids`     → ATR
 *   - `breach.dpa_notified.qes_aar_id`          → AAR (`ar.attestation.v1`)
 *   - `breach.closed.post_breach_anr_id`        → ANR (`ar.notice.v1`)
 *
 * No cross-family corpus is required — composition is pure extraction +
 * indexing. The reverse indexes prove auditor-side roll-ups (cited /
 * citing) work; the coverage report proves per-incident composition
 * accounting works.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AbrBody } from "../src/types.ts";
import {
  buildAbrCoverageReport,
  buildAbrReverseIndexes,
  extractAbrComposition,
} from "../src/composition.ts";
import type { AbrChainReceipt } from "../src/chain.ts";

// ── Body factories ────────────────────────────────────────────────────────────

const ISS = "did:web:controller.example";
const INC_A = "incident-2026-05-19-A";
const INC_B = "incident-2026-05-19-B";

function detectedBody(over: Partial<AbrBody> = {}): AbrBody {
  return {
    event_type: "breach.detected",
    profile: "breach.gdpr.art33",
    incident_correlation_id: INC_A,
    detected_at: "2026-05-19T08:00:00Z",
    severity_class: "high_risk",
    affected_data_categories: ["email"],
    affected_data_hash: "sha256:abc",
    affected_count: 100,
    jurisdiction: "EU",
    affected_aer_ids: null,
    assessment_method_hash: null,
    notification_uri: null,
    notification_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    post_breach_anr_id: null,
    qes_aar_id: null,
    ...over,
  } as AbrBody;
}

function assessedBody(over: Partial<AbrBody> = {}): AbrBody {
  return {
    event_type: "breach.assessed",
    profile: "breach.gdpr.art33",
    incident_correlation_id: INC_A,
    severity_class: "risk",
    assessment_method_hash: "sha256:method",
    detected_at: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    notification_uri: null,
    notification_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    affected_aer_ids: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    post_breach_anr_id: null,
    qes_aar_id: null,
    ...over,
  } as AbrBody;
}

function dpaNotifiedBody(over: Partial<AbrBody> = {}): AbrBody {
  return {
    event_type: "breach.dpa_notified",
    profile: "breach.gdpr.art33",
    incident_correlation_id: INC_A,
    notification_uri: "https://example.test/notif",
    notification_hash: "sha256:notif",
    dpa_reference_id: null,
    notification_phase: null,
    qes_aar_id: null,
    detected_at: null,
    severity_class: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    assessment_method_hash: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    affected_aer_ids: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    post_breach_anr_id: null,
    ...over,
  } as AbrBody;
}

function containedBody(over: Partial<AbrBody> = {}): AbrBody {
  return {
    event_type: "breach.contained",
    profile: "breach.gdpr.art33",
    incident_correlation_id: INC_A,
    containment_at: "2026-05-22T10:00:00Z",
    containment_summary_hash: "sha256:summary",
    containment_attestation: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    detected_at: null,
    severity_class: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    assessment_method_hash: null,
    notification_uri: null,
    notification_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    affected_aer_ids: null,
    post_breach_anr_id: null,
    qes_aar_id: null,
    ...over,
  } as AbrBody;
}

function closedBody(over: Partial<AbrBody> = {}): AbrBody {
  return {
    event_type: "breach.closed",
    profile: "breach.gdpr.art33",
    incident_correlation_id: INC_A,
    closed_at: "2026-05-25T12:00:00Z",
    closure_dpa_reference_id: null,
    post_breach_anr_id: null,
    detected_at: null,
    severity_class: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    assessment_method_hash: null,
    notification_uri: null,
    notification_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    affected_aer_ids: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    qes_aar_id: null,
    ...over,
  } as AbrBody;
}

function r(id: string, body: AbrBody, prev: string | null = null): AbrChainReceipt {
  return { id, iss: ISS, prev, body };
}

// ── extractAbrComposition ─────────────────────────────────────────────────────

test("extractAbrComposition: breach.detected returns affected_aer_ids only", () => {
  const body = detectedBody({ affected_aer_ids: ["aer-1", "aer-2"] });
  const links = extractAbrComposition(body);
  assert.deepEqual(links.affectedAerIds, ["aer-1", "aer-2"]);
  assert.deepEqual(links.containmentRemediationArrIds, []);
  assert.deepEqual(links.transferSuspensionAtrIds, []);
  assert.equal(links.postBreachAnrId, null);
  assert.equal(links.qesAarId, null);
});

test("extractAbrComposition: breach.detected with null AER list collapses to []", () => {
  const body = detectedBody({ affected_aer_ids: null });
  const links = extractAbrComposition(body);
  assert.deepEqual(links.affectedAerIds, []);
});

test("extractAbrComposition: breach.contained returns both ARR + ATR refs", () => {
  const body = containedBody({
    containment_remediation_arr_ids: ["arr-x"],
    transfer_suspension_atr_ids: ["atr-y", "atr-z"],
  });
  const links = extractAbrComposition(body);
  assert.deepEqual(links.containmentRemediationArrIds, ["arr-x"]);
  assert.deepEqual(links.transferSuspensionAtrIds, ["atr-y", "atr-z"]);
  assert.deepEqual(links.affectedAerIds, []);
  assert.equal(links.postBreachAnrId, null);
  assert.equal(links.qesAarId, null);
});

test("extractAbrComposition: breach.contained with mixed null/empty arrays", () => {
  const body = containedBody({
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: [],
  });
  const links = extractAbrComposition(body);
  assert.deepEqual(links.containmentRemediationArrIds, []);
  assert.deepEqual(links.transferSuspensionAtrIds, []);
});

test("extractAbrComposition: breach.dpa_notified returns qes_aar_id only", () => {
  const body = dpaNotifiedBody({ qes_aar_id: "aar-qes" });
  const links = extractAbrComposition(body);
  assert.equal(links.qesAarId, "aar-qes");
  assert.deepEqual(links.affectedAerIds, []);
  assert.equal(links.postBreachAnrId, null);
});

test("extractAbrComposition: breach.dpa_notified with null qes carries through", () => {
  const body = dpaNotifiedBody({ qes_aar_id: null });
  const links = extractAbrComposition(body);
  assert.equal(links.qesAarId, null);
});

test("extractAbrComposition: breach.closed returns post_breach_anr_id only", () => {
  const body = closedBody({ post_breach_anr_id: "anr-post" });
  const links = extractAbrComposition(body);
  assert.equal(links.postBreachAnrId, "anr-post");
  assert.deepEqual(links.affectedAerIds, []);
  assert.equal(links.qesAarId, null);
});

test("extractAbrComposition: non-composition events yield all-empty links", () => {
  const links = extractAbrComposition(assessedBody());
  assert.deepEqual(links.affectedAerIds, []);
  assert.deepEqual(links.containmentRemediationArrIds, []);
  assert.deepEqual(links.transferSuspensionAtrIds, []);
  assert.equal(links.postBreachAnrId, null);
  assert.equal(links.qesAarId, null);
});

// ── buildAbrReverseIndexes — per-target ───────────────────────────────────────

test("buildAbrReverseIndexes: ARR target bucket pairs citing breach.contained receipts", () => {
  const c1 = r("ABR-1", containedBody({
    containment_remediation_arr_ids: ["arr-a", "arr-b"],
  }));
  const c2 = r("ABR-2", containedBody({
    incident_correlation_id: INC_B,
    containment_remediation_arr_ids: ["arr-a"],
  }));
  const { arrIndex } = buildAbrReverseIndexes([c1, c2]);

  assert.equal(arrIndex.size, 2);
  assert.deepEqual(
    arrIndex.get("arr-a")?.map((x) => x.id),
    ["ABR-1", "ABR-2"],
  );
  assert.deepEqual(arrIndex.get("arr-b")?.map((x) => x.id), ["ABR-1"]);
});

test("buildAbrReverseIndexes: ATR target bucket independent of ARR bucket", () => {
  const c1 = r("ABR-1", containedBody({
    containment_remediation_arr_ids: ["arr-shared"],
    transfer_suspension_atr_ids: ["atr-1"],
  }));
  const { arrIndex, atrIndex } = buildAbrReverseIndexes([c1]);
  assert.equal(arrIndex.has("arr-shared"), true);
  assert.equal(atrIndex.has("atr-1"), true);
  assert.equal(arrIndex.has("atr-1"), false);
  assert.equal(atrIndex.has("arr-shared"), false);
});

test("buildAbrReverseIndexes: AER bucket only populated on breach.detected", () => {
  const det = r("ABR-DET", detectedBody({ affected_aer_ids: ["aer-1"] }));
  const con = r(
    "ABR-CON",
    containedBody({ containment_remediation_arr_ids: ["aer-1"] }),
  );
  const { aerIndex, arrIndex } = buildAbrReverseIndexes([det, con]);

  assert.deepEqual(aerIndex.get("aer-1")?.map((x) => x.id), ["ABR-DET"]);
  assert.deepEqual(arrIndex.get("aer-1")?.map((x) => x.id), ["ABR-CON"]);
});

test("buildAbrReverseIndexes: ANR bucket only populated on breach.closed", () => {
  const cl = r("ABR-CL", closedBody({ post_breach_anr_id: "anr-1" }));
  const { anrIndex } = buildAbrReverseIndexes([cl]);
  assert.deepEqual(anrIndex.get("anr-1")?.map((x) => x.id), ["ABR-CL"]);
});

test("buildAbrReverseIndexes: AAR bucket only populated on breach.dpa_notified", () => {
  const dn = r("ABR-DN", dpaNotifiedBody({ qes_aar_id: "aar-1" }));
  const { aarIndex } = buildAbrReverseIndexes([dn]);
  assert.deepEqual(aarIndex.get("aar-1")?.map((x) => x.id), ["ABR-DN"]);
});

test("buildAbrReverseIndexes: receipts with no composition refs contribute nothing", () => {
  const idx = buildAbrReverseIndexes([
    r("ABR-A", assessedBody()),
    r("ABR-B", detectedBody({ affected_aer_ids: null })),
    r("ABR-C", closedBody({ post_breach_anr_id: null })),
  ]);
  assert.equal(idx.arrIndex.size, 0);
  assert.equal(idx.atrIndex.size, 0);
  assert.equal(idx.aerIndex.size, 0);
  assert.equal(idx.anrIndex.size, 0);
  assert.equal(idx.aarIndex.size, 0);
});

test("buildAbrReverseIndexes: empty-string id refs are skipped (defensive)", () => {
  const c = r("ABR-1", containedBody({
    containment_remediation_arr_ids: [""],
  }));
  const cl = r("ABR-2", closedBody({ post_breach_anr_id: "" }));
  const dn = r("ABR-3", dpaNotifiedBody({ qes_aar_id: "" }));
  const idx = buildAbrReverseIndexes([c, cl, dn]);
  assert.equal(idx.arrIndex.has(""), false);
  assert.equal(idx.anrIndex.has(""), false);
  assert.equal(idx.aarIndex.has(""), false);
});

test("buildAbrReverseIndexes: same receipt citing same target twice appears once", () => {
  const c = r("ABR-DUP", containedBody({
    containment_remediation_arr_ids: ["arr-1", "arr-1"],
  }));
  const { arrIndex } = buildAbrReverseIndexes([c]);
  assert.deepEqual(arrIndex.get("arr-1")?.map((x) => x.id), ["ABR-DUP"]);
});

test("buildAbrReverseIndexes: empty input yields empty indexes (sanity)", () => {
  const idx = buildAbrReverseIndexes([]);
  assert.equal(idx.arrIndex.size, 0);
  assert.equal(idx.atrIndex.size, 0);
  assert.equal(idx.aerIndex.size, 0);
  assert.equal(idx.anrIndex.size, 0);
  assert.equal(idx.aarIndex.size, 0);
});

// ── buildAbrCoverageReport ────────────────────────────────────────────────────

test("buildAbrCoverageReport: empty corpus", () => {
  const rep = buildAbrCoverageReport([]);
  assert.equal(rep.totalAbrReceipts, 0);
  assert.deepEqual(rep.incidentIds, []);
  assert.deepEqual(rep.citedArrIds, []);
  assert.deepEqual(rep.citedAtrIds, []);
  assert.deepEqual(rep.citedAerIds, []);
  assert.deepEqual(rep.citedAnrIds, []);
  assert.deepEqual(rep.citedAarIds, []);
  assert.deepEqual(rep.incidentsWithAerCoverage, []);
  assert.deepEqual(rep.incidentsWithContainmentComposition, []);
  assert.deepEqual(rep.incidentsWithPostBreachAnr, []);
  assert.deepEqual(rep.incidentsWithQesAttestation, []);
});

test("buildAbrCoverageReport: full single-incident lifecycle with every composition edge", () => {
  const det = r("ABR-DET", detectedBody({
    affected_aer_ids: ["aer-2", "aer-1"],
  }));
  const ass = r("ABR-ASS", assessedBody(), "ABR-DET");
  const dn = r("ABR-DN", dpaNotifiedBody({ qes_aar_id: "aar-1" }), "ABR-ASS");
  const con = r("ABR-CON", containedBody({
    containment_remediation_arr_ids: ["arr-2", "arr-1"],
    transfer_suspension_atr_ids: ["atr-1"],
  }), "ABR-DN");
  const cl = r("ABR-CL", closedBody({ post_breach_anr_id: "anr-1" }), "ABR-CON");

  const rep = buildAbrCoverageReport([det, ass, dn, con, cl]);

  assert.equal(rep.totalAbrReceipts, 5);
  assert.deepEqual(rep.incidentIds, [INC_A]);
  // Sorted lexicographically.
  assert.deepEqual(rep.citedAerIds, ["aer-1", "aer-2"]);
  assert.deepEqual(rep.citedArrIds, ["arr-1", "arr-2"]);
  assert.deepEqual(rep.citedAtrIds, ["atr-1"]);
  assert.deepEqual(rep.citedAnrIds, ["anr-1"]);
  assert.deepEqual(rep.citedAarIds, ["aar-1"]);

  assert.deepEqual(rep.incidentsWithAerCoverage, [INC_A]);
  assert.deepEqual(rep.incidentsWithContainmentComposition, [INC_A]);
  assert.deepEqual(rep.incidentsWithPostBreachAnr, [INC_A]);
  assert.deepEqual(rep.incidentsWithQesAttestation, [INC_A]);
});

test("buildAbrCoverageReport: incident without composition refs is counted but not flagged", () => {
  const det = r("ABR-DET", detectedBody({ affected_aer_ids: null }));
  const cl = r("ABR-CL", closedBody({ post_breach_anr_id: null }), "ABR-DET");

  const rep = buildAbrCoverageReport([det, cl]);
  assert.equal(rep.totalAbrReceipts, 2);
  assert.deepEqual(rep.incidentIds, [INC_A]);
  assert.deepEqual(rep.incidentsWithAerCoverage, []);
  assert.deepEqual(rep.incidentsWithPostBreachAnr, []);
});

test("buildAbrCoverageReport: two incidents — only one carries each composition edge", () => {
  const detA = r("A-DET", detectedBody({
    incident_correlation_id: INC_A,
    affected_aer_ids: ["aer-A"],
  }));
  const detB = r("B-DET", detectedBody({
    incident_correlation_id: INC_B,
    affected_aer_ids: null,
  }));
  const conB = r("B-CON", containedBody({
    incident_correlation_id: INC_B,
    transfer_suspension_atr_ids: ["atr-B"],
  }));

  const rep = buildAbrCoverageReport([detA, detB, conB]);

  assert.deepEqual(rep.incidentIds, [INC_A, INC_B].sort());
  assert.deepEqual(rep.incidentsWithAerCoverage, [INC_A]);
  assert.deepEqual(rep.incidentsWithContainmentComposition, [INC_B]);
  assert.deepEqual(rep.citedAerIds, ["aer-A"]);
  assert.deepEqual(rep.citedAtrIds, ["atr-B"]);
});

test("buildAbrCoverageReport: composition field on wrong event_type does NOT flag incident", () => {
  // A `breach.contained` event with both ARR and ATR populated flags only
  // `incidentsWithContainmentComposition` — never AER (AER is detected-only).
  const con = r("ABR-CON", containedBody({
    containment_remediation_arr_ids: ["arr-1"],
  }));
  const rep = buildAbrCoverageReport([con]);
  assert.deepEqual(rep.incidentsWithContainmentComposition, [INC_A]);
  assert.deepEqual(rep.incidentsWithAerCoverage, []);
  assert.deepEqual(rep.incidentsWithPostBreachAnr, []);
  assert.deepEqual(rep.incidentsWithQesAttestation, []);
});

// ── Cross-receipt audit-fix C5 anchor ─────────────────────────────────────────

test("audit-fix C5 anchor: all 5 composition fields ship as auditor-visible refs", () => {
  // One incident with every C5 composition edge populated; one negative
  // incident where every C5 field is null. The combined report should
  // distinguish them across all five surfaces.
  const det = r("A-DET", detectedBody({
    incident_correlation_id: INC_A,
    affected_aer_ids: ["aer-A1"],
  }));
  const dn = r("A-DN", dpaNotifiedBody({
    incident_correlation_id: INC_A,
    qes_aar_id: "aar-A1",
  }));
  const con = r("A-CON", containedBody({
    incident_correlation_id: INC_A,
    containment_remediation_arr_ids: ["arr-A1"],
    transfer_suspension_atr_ids: ["atr-A1"],
  }));
  const cl = r("A-CL", closedBody({
    incident_correlation_id: INC_A,
    post_breach_anr_id: "anr-A1",
  }));

  const detB = r("B-DET", detectedBody({
    incident_correlation_id: INC_B,
    affected_aer_ids: null,
  }));
  const dnB = r("B-DN", dpaNotifiedBody({
    incident_correlation_id: INC_B,
    qes_aar_id: null,
  }));
  const conB = r("B-CON", containedBody({
    incident_correlation_id: INC_B,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
  }));
  const clB = r("B-CL", closedBody({
    incident_correlation_id: INC_B,
    post_breach_anr_id: null,
  }));

  const idx = buildAbrReverseIndexes([det, dn, con, cl, detB, dnB, conB, clB]);
  const rep = buildAbrCoverageReport([det, dn, con, cl, detB, dnB, conB, clB]);

  // Every C5 surface is auditor-visible for incident A.
  assert.deepEqual(idx.aerIndex.get("aer-A1")?.map((x) => x.id), ["A-DET"]);
  assert.deepEqual(idx.arrIndex.get("arr-A1")?.map((x) => x.id), ["A-CON"]);
  assert.deepEqual(idx.atrIndex.get("atr-A1")?.map((x) => x.id), ["A-CON"]);
  assert.deepEqual(idx.anrIndex.get("anr-A1")?.map((x) => x.id), ["A-CL"]);
  assert.deepEqual(idx.aarIndex.get("aar-A1")?.map((x) => x.id), ["A-DN"]);

  // Incident B contributes no composition refs to any of the 5 surfaces.
  assert.deepEqual(rep.incidentsWithAerCoverage, [INC_A]);
  assert.deepEqual(rep.incidentsWithContainmentComposition, [INC_A]);
  assert.deepEqual(rep.incidentsWithPostBreachAnr, [INC_A]);
  assert.deepEqual(rep.incidentsWithQesAttestation, [INC_A]);
});
