/**
 * Tests for the envelope-`prev` chain walker (spec §6.1 + §6.2 +
 * D10-ABR-3 + D10-ABR-5).
 *
 * Builds in-memory chain fixtures via thin AbrChainReceipt projections (no
 * envelope-level cryptography needed — the walker contract treats receipts
 * as already body-verified). Coverage targets each result flag plus the
 * happy-path multi-hop walk.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ABR_DEFAULT_DEPTH_LIMIT,
  ABR_DEPTH_LIMIT_MAX,
  ABR_DEPTH_LIMIT_MIN,
} from "../src/types.ts";
import type { AbrBody } from "../src/types.ts";
import {
  buildAbrChainIndex,
  walkAbrChain,
} from "../src/chain.ts";
import type { AbrChainReceipt } from "../src/chain.ts";

// ── Body factories (minimal — only the fields the walker reads) ───────────────

const ISS = "did:web:controller.example";
const INC = "incident-2026-05-19-001";

function detectedBody(over: Partial<AbrBody> = {}): AbrBody {
  return {
    event_type: "breach.detected",
    profile: "breach.gdpr.art33",
    incident_correlation_id: INC,
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
    incident_correlation_id: INC,
    severity_class: "risk",
    assessment_method_hash: "sha256:meth",
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

function closedBody(over: Partial<AbrBody> = {}): AbrBody {
  return {
    event_type: "breach.closed",
    profile: "breach.gdpr.art33",
    incident_correlation_id: INC,
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

function makeReceipt(
  id: string,
  prev: string | null,
  body: AbrBody,
  iss: string = ISS,
): AbrChainReceipt {
  return { id, iss, prev, body };
}

// ── Constants ────────────────────────────────────────────────────────────────

test("constants are sensible", () => {
  assert.equal(ABR_DEPTH_LIMIT_MIN, 32);
  assert.equal(ABR_DEPTH_LIMIT_MAX, 1024);
  assert.equal(ABR_DEFAULT_DEPTH_LIMIT, 256);
});

// ── Index ────────────────────────────────────────────────────────────────────

test("buildAbrChainIndex de-dupes by id (first wins)", () => {
  const r1 = makeReceipt("A", null, detectedBody());
  const r2 = makeReceipt("A", null, closedBody());
  const ix = buildAbrChainIndex([r1, r2]);
  assert.equal(ix.byId.size, 1);
  assert.equal(ix.byId.get("A")?.body.event_type, "breach.detected");
});

test("buildAbrChainIndex on empty list returns empty index", () => {
  const ix = buildAbrChainIndex([]);
  assert.equal(ix.byId.size, 0);
});

// ── Happy path ───────────────────────────────────────────────────────────────

test("walks a 3-hop chain (closed → assessed → detected) to detected head", () => {
  const det = makeReceipt("DET", null, detectedBody());
  const ass = makeReceipt("ASS", "DET", assessedBody());
  const clo = makeReceipt("CLO", "ASS", closedBody());
  const ix = buildAbrChainIndex([det, ass, clo]);

  const r = walkAbrChain("CLO", ix);
  assert.equal(r.hops.length, 3);
  assert.equal(r.hops[0]?.id, "CLO");
  assert.equal(r.hops[1]?.id, "ASS");
  assert.equal(r.hops[2]?.id, "DET");
  assert.equal(r.head?.id, "DET");
  assert.equal(r.cycle, false);
  assert.equal(r.truncated, false);
  assert.equal(r.dangling, false);
  assert.equal(r.iss_inconsistent, false);
  assert.equal(r.incident_correlation_id_inconsistent, false);
  assert.equal(r.chain_head_not_detected, false);
});

test("startId not in index → empty hops, no head", () => {
  const ix = buildAbrChainIndex([]);
  const r = walkAbrChain("missing", ix);
  assert.equal(r.hops.length, 0);
  assert.equal(r.head, null);
  assert.equal(r.dangling, true);
});

// ── Cycle detection ──────────────────────────────────────────────────────────

test("cycle: A → B → A surfaces cycle:true and head:null", () => {
  const a = makeReceipt("A", "B", assessedBody());
  const b = makeReceipt("B", "A", detectedBody());
  const ix = buildAbrChainIndex([a, b]);

  const r = walkAbrChain("A", ix);
  assert.equal(r.cycle, true);
  assert.equal(r.head, null);
});

test("self-cycle: A → A surfaces cycle:true", () => {
  const a = makeReceipt("A", "A", detectedBody());
  const ix = buildAbrChainIndex([a]);

  const r = walkAbrChain("A", ix);
  assert.equal(r.cycle, true);
  assert.equal(r.head, null);
});

// ── Dangling reference ───────────────────────────────────────────────────────

test("dangling: A → B but B is missing surfaces dangling:true", () => {
  const a = makeReceipt("A", "B", closedBody());
  const ix = buildAbrChainIndex([a]);

  const r = walkAbrChain("A", ix);
  assert.equal(r.dangling, true);
  assert.equal(r.head, null);
  assert.equal(r.hops.length, 1);
});

// ── Depth limit ──────────────────────────────────────────────────────────────

test("depthLimit below floor (3) clamps up to MIN (32) — walk completes", () => {
  // 5 hops: r4 → r3 → r2 → r1 → r0 (detected head). depthLimit 3 clamps to 32
  // so the walk completes.
  const r0 = makeReceipt("R0", null, detectedBody());
  const r1 = makeReceipt("R1", "R0", assessedBody());
  const r2 = makeReceipt("R2", "R1", assessedBody());
  const r3 = makeReceipt("R3", "R2", assessedBody());
  const r4 = makeReceipt("R4", "R3", closedBody());
  const ix = buildAbrChainIndex([r0, r1, r2, r3, r4]);

  const r = walkAbrChain("R4", ix, { depthLimit: 3 });
  assert.equal(r.truncated, false);
  assert.equal(r.head?.id, "R0");
});

test("truncated: explicit floor limit (32) on 33-hop chain truncates", () => {
  const receipts: AbrChainReceipt[] = [];
  receipts.push(makeReceipt("R0", null, detectedBody()));
  for (let i = 1; i < 33; i++) {
    receipts.push(makeReceipt(`R${i}`, `R${i - 1}`, assessedBody()));
  }
  const ix = buildAbrChainIndex(receipts);

  const r = walkAbrChain("R32", ix, { depthLimit: 32 });
  assert.equal(r.truncated, true);
  assert.equal(r.head, null);
  assert.equal(r.hops.length, 32);
});

test("depthLimit above ceiling clamps to MAX", () => {
  const det = makeReceipt("D", null, detectedBody());
  const ix = buildAbrChainIndex([det]);
  const r = walkAbrChain("D", ix, { depthLimit: 1_000_000 });
  assert.equal(r.head?.id, "D");
  assert.equal(r.truncated, false);
});

// ── iss consistency ─────────────────────────────────────────────────────────

test("iss_inconsistent surfaces when two hops carry different controllers", () => {
  const det = makeReceipt("DET", null, detectedBody(), "did:web:a.example");
  const ass = makeReceipt("ASS", "DET", assessedBody(), "did:web:b.example");
  const ix = buildAbrChainIndex([det, ass]);

  const r = walkAbrChain("ASS", ix);
  assert.equal(r.iss_inconsistent, true);
  // The walker does not abort — head still reached.
  assert.equal(r.head?.id, "DET");
});

test("iss_inconsistent stays false when all hops share controller", () => {
  const det = makeReceipt("DET", null, detectedBody());
  const ass = makeReceipt("ASS", "DET", assessedBody());
  const ix = buildAbrChainIndex([det, ass]);

  const r = walkAbrChain("ASS", ix);
  assert.equal(r.iss_inconsistent, false);
});

// ── incident_correlation_id parity (D10-ABR-3) ──────────────────────────────

test("incident_correlation_id_inconsistent surfaces on mismatch (D10-ABR-3)", () => {
  const det = makeReceipt(
    "DET",
    null,
    detectedBody({ incident_correlation_id: "incident-A" }),
  );
  const ass = makeReceipt(
    "ASS",
    "DET",
    assessedBody({ incident_correlation_id: "incident-B" }),
  );
  const ix = buildAbrChainIndex([det, ass]);

  const r = walkAbrChain("ASS", ix);
  assert.equal(r.incident_correlation_id_inconsistent, true);
  // Walker does not abort on this either.
  assert.equal(r.head?.id, "DET");
});

test("incident_correlation_id_inconsistent stays false when all hops share id", () => {
  const det = makeReceipt("DET", null, detectedBody());
  const ass = makeReceipt("ASS", "DET", assessedBody());
  const clo = makeReceipt("CLO", "ASS", closedBody());
  const ix = buildAbrChainIndex([det, ass, clo]);

  const r = walkAbrChain("CLO", ix);
  assert.equal(r.incident_correlation_id_inconsistent, false);
});

// ── chain_head_not_detected (D10-ABR-5) ─────────────────────────────────────

test("chain_head_not_detected fires when head is not breach.detected", () => {
  // Misconfigured chain head: prev:null on an assessed event (spec D10-ABR-5
  // violation — head MUST be breach.detected).
  const ass = makeReceipt("ASS", null, assessedBody());
  const ix = buildAbrChainIndex([ass]);

  const r = walkAbrChain("ASS", ix);
  assert.equal(r.head?.id, "ASS");
  assert.equal(r.chain_head_not_detected, true);
});

test("chain_head_not_detected stays false when head is breach.detected", () => {
  const det = makeReceipt("DET", null, detectedBody());
  const ix = buildAbrChainIndex([det]);

  const r = walkAbrChain("DET", ix);
  assert.equal(r.head?.id, "DET");
  assert.equal(r.chain_head_not_detected, false);
});

test("chain_head_not_detected stays false when walk aborts (no head)", () => {
  const a = makeReceipt("A", "B", assessedBody());
  const ix = buildAbrChainIndex([a]);

  const r = walkAbrChain("A", ix, { depthLimit: 32 });
  assert.equal(r.head, null);
  assert.equal(r.chain_head_not_detected, false);
});

// ── Single-hop edge case ────────────────────────────────────────────────────

test("single-hop walk on breach.detected returns it as head", () => {
  const det = makeReceipt("D", null, detectedBody());
  const ix = buildAbrChainIndex([det]);

  const r = walkAbrChain("D", ix);
  assert.equal(r.hops.length, 1);
  assert.equal(r.head?.id, "D");
  assert.equal(r.chain_head_not_detected, false);
});
