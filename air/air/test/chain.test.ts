/**
 * Tests for the AIR envelope-`prev` chain walker (spec §6.1 + §6.2 +
 * D10-AIR-2/-3/-4/-7).
 *
 * Builds in-memory chain fixtures via thin AirChainReceipt projections (no
 * envelope-level cryptography needed — the walker contract treats receipts
 * as already body-verified). Coverage targets each result flag, each
 * cross-event hard-invalid reason, and each informational warning.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AIR_DEFAULT_DEPTH_LIMIT,
  AIR_DEPTH_LIMIT_MAX,
  AIR_DEPTH_LIMIT_MIN,
} from "../src/types.ts";
import {
  buildAirChainIndex,
  walkAirChain,
} from "../src/chain.ts";
import type { AirChainReceipt } from "../src/chain.ts";
import {
  completed,
  dpoAdvised,
  priorConsultationInitiated,
  priorConsultationResolved,
  processingAuthorised,
  reviewed,
  scopeLocked,
  stakeholdersConsulted,
  terminated,
  thresholdTriggered,
} from "./_helpers/bodies.ts";
import type { AirBody } from "../src/types.ts";

const ISS = "did:web:controller.example";
const ISS_OTHER = "did:web:other-controller.example";

// ── Receipt-builder shorthand ────────────────────────────────────────────────

function r(
  id: string,
  body: AirBody,
  opts: { prev?: string | null; iss?: string; iat?: string } = {},
): AirChainReceipt {
  return {
    id,
    iss: opts.iss ?? ISS,
    iat: opts.iat ?? "2026-05-19T08:00:00Z",
    prev: opts.prev ?? null,
    body,
  };
}

// ── Walker basics ────────────────────────────────────────────────────────────

test("walker: depth-limit clamping constants", () => {
  assert.equal(AIR_DEPTH_LIMIT_MIN, 32);
  assert.equal(AIR_DEPTH_LIMIT_MAX, 1024);
  assert.equal(AIR_DEFAULT_DEPTH_LIMIT, 256);
});

test("walker: unknown startId returns empty result", () => {
  const idx = buildAirChainIndex([]);
  const res = walkAirChain("nonexistent", idx);
  assert.deepEqual(res.hops, []);
  assert.equal(res.head, null);
  assert.equal(res.dangling, true);
});

test("walker: single threshold_triggered (prev=null) is the head", () => {
  const t = r("t", thresholdTriggered());
  const idx = buildAirChainIndex([t]);
  const res = walkAirChain("t", idx);
  assert.equal(res.head?.id, "t");
  assert.equal(res.hops.length, 1);
  assert.equal(res.predecessor_id, null);
  assert.equal(res.cycle, false);
  assert.equal(res.truncated, false);
  assert.equal(res.dangling, false);
  assert.equal(res.chain_head_not_threshold_triggered, false);
});

test("walker: multi-hop walk stops at first threshold_triggered", () => {
  const t = r("t", thresholdTriggered());
  const s = r("s", scopeLocked(), { prev: "t" });
  const c = r("c", completed(), { prev: "s" });
  const idx = buildAirChainIndex([t, s, c]);
  const res = walkAirChain("c", idx);
  assert.equal(res.head?.id, "t");
  assert.equal(res.hops.map((h) => h.id).join(","), "c,s,t");
  assert.equal(res.predecessor_id, null);
  assert.deepEqual(res.hard_invalid_reasons, []);
});

test("walker: cycle detection", () => {
  const a = r("a", scopeLocked(), { prev: "b" });
  const b = r("b", scopeLocked(), { prev: "a" });
  const idx = buildAirChainIndex([a, b]);
  const res = walkAirChain("a", idx);
  assert.equal(res.cycle, true);
  assert.equal(res.head, null);
});

test("walker: dangling prev flagged", () => {
  const c = r("c", completed(), { prev: "missing" });
  const idx = buildAirChainIndex([c]);
  const res = walkAirChain("c", idx);
  assert.equal(res.dangling, true);
  assert.equal(res.head, null);
});

test("walker: depthLimit truncates a long pre-head walk", () => {
  // Build 60 scope_locked hops behind a single threshold_triggered head.
  // depthLimit clamps to 32 (the floor) — we expect a truncation before the
  // head appears.
  const t = r("t-final", thresholdTriggered());
  const middle: AirChainReceipt[] = [];
  for (let i = 0; i < 60; i++) {
    const prev = i === 0 ? "t-final" : `s-${i - 1}`;
    middle.push(r(`s-${i}`, scopeLocked(), { prev }));
  }
  const idx = buildAirChainIndex([...middle, t]);
  const res = walkAirChain("s-59", idx, { depthLimit: 5 });
  assert.equal(res.truncated, true);
  assert.equal(res.head, null);
  // floor enforcement: walker clamps 5 up to 32 then truncates
  assert.equal(res.hops.length, AIR_DEPTH_LIMIT_MIN);
});

test("walker: iss_inconsistent flagged when controller DID changes mid-chain", () => {
  const t = r("t", thresholdTriggered());
  const s = r("s", scopeLocked(), { prev: "t", iss: ISS_OTHER });
  const idx = buildAirChainIndex([t, s]);
  const res = walkAirChain("s", idx);
  assert.equal(res.iss_inconsistent, true);
});

test("walker: air_receipt_id_inconsistent flagged on D10-AIR-2 drift", () => {
  const t = r("t", thresholdTriggered());
  const s = r("s", scopeLocked({ air_receipt_id: "air-drift-999" }), { prev: "t" });
  const idx = buildAirChainIndex([t, s]);
  const res = walkAirChain("s", idx);
  assert.equal(res.air_receipt_id_inconsistent, true);
});

test("walker: chain_head_not_threshold_triggered when head is a different event", () => {
  // Pathological corpus: a scope_locked with prev=null. The walker stops at
  // the first prev=null receipt and flags it.
  const orphan = r("orphan", scopeLocked());
  const idx = buildAirChainIndex([orphan]);
  const res = walkAirChain("orphan", idx);
  assert.equal(res.head?.id, "orphan");
  assert.equal(res.chain_head_not_threshold_triggered, true);
});

// ── §6.2 rule 3 — processing_activity parity ─────────────────────────────────

test("walker: rule 3a — processing_activity_id drift HARD-invalid", () => {
  const t = r("t", thresholdTriggered());
  const s = r("s", scopeLocked({ processing_activity_id: "processing-activity-different" }), {
    prev: "t",
  });
  const idx = buildAirChainIndex([t, s]);
  const res = walkAirChain("s", idx);
  assert.ok(res.hard_invalid_reasons.includes("processing_activity_drift"));
});

test("walker: rule 3b — happy path leaves hard-invalid empty", () => {
  const t = r("t", thresholdTriggered());
  const s = r("s", scopeLocked(), { prev: "t" });
  const idx = buildAirChainIndex([t, s]);
  const res = walkAirChain("s", idx);
  assert.deepEqual(res.hard_invalid_reasons, []);
});

// ── §6.2 rule 4 / D10-AIR-7 — dpia_artifact_hash immutability ────────────────

test("walker: dpia_artifact_hash_drift HARD-invalid on second completed", () => {
  const t = r("t", thresholdTriggered());
  const c1 = r("c1", completed(), { prev: "t" });
  const c2 = r(
    "c2",
    completed({ dpia_artifact_hash: "sha256:dpia-artifact-drift" }),
    { prev: "c1" },
  );
  const idx = buildAirChainIndex([t, c1, c2]);
  const res = walkAirChain("c2", idx);
  assert.ok(res.hard_invalid_reasons.includes("dpia_artifact_hash_drift"));
});

test("walker: two completed events with identical artifact hash accepted", () => {
  const t = r("t", thresholdTriggered());
  const c1 = r("c1", completed(), { prev: "t" });
  const c2 = r("c2", completed(), { prev: "c1" });
  const idx = buildAirChainIndex([t, c1, c2]);
  const res = walkAirChain("c2", idx);
  assert.deepEqual(res.hard_invalid_reasons, []);
});

// ── §6.2 rule 5 / D10-AIR-4 — prior-consultation gate ────────────────────────

test("walker: art36_prior_consultation_skipped on high-risk authorise without resolved", () => {
  const t = r("t", thresholdTriggered());
  const c = r("c", completed({ residual_risk_level: "high" }), { prev: "t" });
  const auth = r("auth", processingAuthorised(), { prev: "c" });
  const idx = buildAirChainIndex([t, c, auth]);
  const res = walkAirChain("auth", idx);
  assert.ok(res.hard_invalid_reasons.includes("art36_prior_consultation_skipped"));
});

test("walker: high-risk + prior_consultation_resolved + authorised passes", () => {
  const t = r("t", thresholdTriggered());
  const c = r("c", completed({ residual_risk_level: "high" }), { prev: "t" });
  const pci = r("pci", priorConsultationInitiated(), {
    prev: "c",
    iat: "2026-06-01T08:00:00Z",
  });
  const pcr = r("pcr", priorConsultationResolved(), {
    prev: "pci",
    iat: "2026-07-15T08:00:00Z",
  });
  const auth = r("auth", processingAuthorised(), { prev: "pcr" });
  const idx = buildAirChainIndex([t, c, pci, pcr, auth]);
  const res = walkAirChain("auth", idx);
  assert.deepEqual(res.hard_invalid_reasons, []);
});

test("walker: medium-risk authorised without prior-consultation passes", () => {
  const t = r("t", thresholdTriggered());
  const c = r("c", completed({ residual_risk_level: "medium" }), { prev: "t" });
  const auth = r("auth", processingAuthorised(), { prev: "c" });
  const idx = buildAirChainIndex([t, c, auth]);
  const res = walkAirChain("auth", idx);
  assert.deepEqual(res.hard_invalid_reasons, []);
});

test("walker: material-change review resets the high-risk consultation gate", () => {
  // High-risk completed, then material-change reviewed, then a fresh
  // (medium) completed, then authorised — no prior-consultation needed
  // after the reset (a fresh DPIA may follow with lower residual risk).
  const t = r("t", thresholdTriggered());
  const c1 = r("c1", completed({ residual_risk_level: "high" }), { prev: "t" });
  const rev = r("rev", reviewed({ review_outcome: "material_change" }), { prev: "c1" });
  // c2 must keep the same dpia_artifact_hash per D10-AIR-7
  const c2 = r(
    "c2",
    completed({ residual_risk_level: "medium" }),
    { prev: "rev" },
  );
  const auth = r("auth", processingAuthorised(), { prev: "c2" });
  const idx = buildAirChainIndex([t, c1, rev, c2, auth]);
  const res = walkAirChain("auth", idx);
  assert.deepEqual(res.hard_invalid_reasons, []);
});

// ── Scope-rewrite gate (spec §4.2) ───────────────────────────────────────────

test("walker: scope_rewrite_without_review HARD-invalid on second scope_locked", () => {
  const t = r("t", thresholdTriggered());
  const s1 = r("s1", scopeLocked(), { prev: "t" });
  const s2 = r("s2", scopeLocked({ scope_hash: "sha256:scope-v2" }), { prev: "s1" });
  const idx = buildAirChainIndex([t, s1, s2]);
  const res = walkAirChain("s2", idx);
  assert.ok(res.hard_invalid_reasons.includes("scope_rewrite_without_review"));
});

test("walker: second scope_locked AFTER material-change review accepted", () => {
  const t = r("t", thresholdTriggered());
  const s1 = r("s1", scopeLocked(), { prev: "t" });
  const rev = r("rev", reviewed({ review_outcome: "material_change" }), { prev: "s1" });
  const s2 = r("s2", scopeLocked({ scope_hash: "sha256:scope-v2" }), { prev: "rev" });
  const idx = buildAirChainIndex([t, s1, rev, s2]);
  const res = walkAirChain("s2", idx);
  assert.deepEqual(res.hard_invalid_reasons, []);
});

// ── §6.2 rule 7 — re-DPIA inheritance ────────────────────────────────────────

test("walker: re-DPIA — valid predecessor (reviewed/material_change) clean", () => {
  // Predecessor chain
  const t0 = r("t0", thresholdTriggered({ air_receipt_id: "air-old" }));
  const rev0 = r(
    "rev0",
    reviewed({ air_receipt_id: "air-old", review_outcome: "material_change" }),
    { prev: "t0" },
  );
  // Successor chain starts here
  const t1 = r("t1", thresholdTriggered({ air_receipt_id: "air-new" }), {
    prev: "rev0",
  });
  const idx = buildAirChainIndex([t0, rev0, t1]);
  const res = walkAirChain("t1", idx);
  assert.equal(res.head?.id, "t1");
  assert.equal(res.predecessor_id, "rev0");
  assert.deepEqual(res.hard_invalid_reasons, []);
});

test("walker: re-DPIA — superseded predecessor accepted", () => {
  const t0 = r("t0", thresholdTriggered({ air_receipt_id: "air-old" }));
  const rev0 = r(
    "rev0",
    reviewed({ air_receipt_id: "air-old", review_outcome: "superseded" }),
    { prev: "t0" },
  );
  const t1 = r("t1", thresholdTriggered({ air_receipt_id: "air-new" }), { prev: "rev0" });
  const idx = buildAirChainIndex([t0, rev0, t1]);
  const res = walkAirChain("t1", idx);
  assert.deepEqual(res.hard_invalid_reasons, []);
});

test("walker: re-DPIA — predecessor wrong event_type HARD-invalid", () => {
  // Predecessor is a completed, not a reviewed — invalid.
  const t0 = r("t0", thresholdTriggered({ air_receipt_id: "air-old" }));
  const c0 = r("c0", completed({ air_receipt_id: "air-old" }), { prev: "t0" });
  const t1 = r("t1", thresholdTriggered({ air_receipt_id: "air-new" }), { prev: "c0" });
  const idx = buildAirChainIndex([t0, c0, t1]);
  const res = walkAirChain("t1", idx);
  assert.ok(res.hard_invalid_reasons.includes("re_dpia_invalid_predecessor"));
});

test("walker: re-DPIA — predecessor with no_material_change outcome HARD-invalid", () => {
  const t0 = r("t0", thresholdTriggered({ air_receipt_id: "air-old" }));
  const rev0 = r(
    "rev0",
    reviewed({ air_receipt_id: "air-old", review_outcome: "no_material_change" }),
    { prev: "t0" },
  );
  const t1 = r("t1", thresholdTriggered({ air_receipt_id: "air-new" }), { prev: "rev0" });
  const idx = buildAirChainIndex([t0, rev0, t1]);
  const res = walkAirChain("t1", idx);
  assert.ok(res.hard_invalid_reasons.includes("re_dpia_invalid_predecessor"));
});

test("walker: re-DPIA — predecessor signed by different controller HARD-invalid", () => {
  const t0 = r("t0", thresholdTriggered({ air_receipt_id: "air-old" }));
  const rev0 = r(
    "rev0",
    reviewed({ air_receipt_id: "air-old", review_outcome: "material_change" }),
    { prev: "t0", iss: ISS_OTHER },
  );
  const t1 = r("t1", thresholdTriggered({ air_receipt_id: "air-new" }), { prev: "rev0" });
  const idx = buildAirChainIndex([t0, rev0, t1]);
  const res = walkAirChain("t1", idx);
  assert.ok(res.hard_invalid_reasons.includes("re_dpia_invalid_predecessor"));
});

test("walker: re-DPIA — missing predecessor surfaces informational warning", () => {
  const t1 = r("t1", thresholdTriggered({ air_receipt_id: "air-new" }), {
    prev: "rev-missing",
  });
  const idx = buildAirChainIndex([t1]);
  const res = walkAirChain("t1", idx);
  assert.ok(res.warnings.includes("re_dpia_predecessor_missing"));
  assert.deepEqual(res.hard_invalid_reasons, []);
});

// ── Informational warnings ───────────────────────────────────────────────────

test("walker: dpia_review_overdue fires when now > review_due_at and no review since", () => {
  const t = r("t", thresholdTriggered());
  const c = r(
    "c",
    completed({ review_due_at: "2026-06-01T08:00:00Z" }),
    { prev: "t", iat: "2026-05-19T08:00:00Z" },
  );
  const idx = buildAirChainIndex([t, c]);
  const res = walkAirChain("c", idx, { now: new Date("2026-08-01T00:00:00Z") });
  assert.ok(res.warnings.includes("dpia_review_overdue"));
});

test("walker: dpia_review_overdue NOT fired when reviewed lands after completed", () => {
  const t = r("t", thresholdTriggered());
  const c = r(
    "c",
    completed({ review_due_at: "2026-06-01T08:00:00Z" }),
    { prev: "t" },
  );
  const rev = r("rev", reviewed(), { prev: "c", iat: "2026-05-25T00:00:00Z" });
  const idx = buildAirChainIndex([t, c, rev]);
  const res = walkAirChain("rev", idx, { now: new Date("2026-08-01T00:00:00Z") });
  assert.equal(res.warnings.includes("dpia_review_overdue"), false);
});

test("walker: art36_consultation_overdue fires beyond 14 weeks", () => {
  const t = r("t", thresholdTriggered());
  const c = r("c", completed({ residual_risk_level: "high" }), { prev: "t" });
  const pci = r("pci", priorConsultationInitiated(), {
    prev: "c",
    iat: "2026-01-01T00:00:00Z",
  });
  // 15 weeks later → overdue
  const pcr = r("pcr", priorConsultationResolved(), {
    prev: "pci",
    iat: "2026-04-19T00:00:00Z",
  });
  const idx = buildAirChainIndex([t, c, pci, pcr]);
  const res = walkAirChain("pcr", idx);
  assert.ok(res.warnings.includes("art36_consultation_overdue"));
});

test("walker: art36_consultation_overdue NOT fired within 14 weeks", () => {
  const t = r("t", thresholdTriggered());
  const c = r("c", completed({ residual_risk_level: "high" }), { prev: "t" });
  const pci = r("pci", priorConsultationInitiated(), {
    prev: "c",
    iat: "2026-01-01T00:00:00Z",
  });
  // 8 weeks later → within window
  const pcr = r("pcr", priorConsultationResolved(), {
    prev: "pci",
    iat: "2026-02-26T00:00:00Z",
  });
  const idx = buildAirChainIndex([t, c, pci, pcr]);
  const res = walkAirChain("pcr", idx);
  assert.equal(res.warnings.includes("art36_consultation_overdue"), false);
});

test("walker: dpo_commit_drift fires across two dpo_advised events with differing commits", () => {
  const t = r("t", thresholdTriggered());
  const d1 = r("d1", dpoAdvised(), { prev: "t" });
  const d2 = r("d2", dpoAdvised({ dpo_did_or_email_commit: "hmac:dpo-commit-v2" }), {
    prev: "d1",
  });
  const idx = buildAirChainIndex([t, d1, d2]);
  const res = walkAirChain("d2", idx);
  assert.ok(res.warnings.includes("dpo_commit_drift"));
});

test("walker: dpo_commit_drift NOT fired when single dpo_advised event present", () => {
  const t = r("t", thresholdTriggered());
  const d1 = r("d1", dpoAdvised(), { prev: "t" });
  const idx = buildAirChainIndex([t, d1]);
  const res = walkAirChain("d1", idx);
  assert.equal(res.warnings.includes("dpo_commit_drift"), false);
});

test("walker: dpia_post_hoc_warning fires when completed.iat > processing_start_at", () => {
  const t = r(
    "t",
    thresholdTriggered({ processing_start_at: "2026-01-01T00:00:00Z" }),
  );
  const c = r("c", completed(), { prev: "t", iat: "2026-03-01T00:00:00Z" });
  const idx = buildAirChainIndex([t, c]);
  const res = walkAirChain("c", idx);
  assert.ok(res.warnings.includes("dpia_post_hoc_warning"));
});

test("walker: dpia_post_hoc_warning NOT fired when completed.iat ≤ processing_start_at", () => {
  const t = r(
    "t",
    thresholdTriggered({ processing_start_at: "2026-06-01T00:00:00Z" }),
  );
  const c = r("c", completed(), { prev: "t", iat: "2026-03-01T00:00:00Z" });
  const idx = buildAirChainIndex([t, c]);
  const res = walkAirChain("c", idx);
  assert.equal(res.warnings.includes("dpia_post_hoc_warning"), false);
});

// ── End-to-end happy chain ───────────────────────────────────────────────────

test("walker: full high-risk authorise lifecycle clean of HARD reasons", () => {
  const t = r(
    "t",
    thresholdTriggered({ processing_start_at: "2027-01-01T00:00:00Z" }),
    { iat: "2026-05-19T08:00:00Z" },
  );
  const sl = r("sl", scopeLocked(), { prev: "t", iat: "2026-05-20T08:00:00Z" });
  const da = r("da", dpoAdvised(), { prev: "sl", iat: "2026-05-21T08:00:00Z" });
  const st = r("st", stakeholdersConsulted(), { prev: "da", iat: "2026-05-22T08:00:00Z" });
  const cp = r(
    "cp",
    completed({
      residual_risk_level: "high",
      review_due_at: "2027-05-22T08:00:00Z",
    }),
    { prev: "st", iat: "2026-05-23T08:00:00Z" },
  );
  const pci = r("pci", priorConsultationInitiated(), {
    prev: "cp",
    iat: "2026-06-01T00:00:00Z",
  });
  const pcr = r("pcr", priorConsultationResolved(), {
    prev: "pci",
    iat: "2026-07-15T00:00:00Z",
  });
  const auth = r("auth", processingAuthorised(), {
    prev: "pcr",
    iat: "2026-07-16T00:00:00Z",
  });
  const idx = buildAirChainIndex([t, sl, da, st, cp, pci, pcr, auth]);
  const res = walkAirChain("auth", idx, { now: new Date("2026-08-01T00:00:00Z") });
  assert.equal(res.head?.id, "t");
  assert.equal(res.hops.length, 8);
  assert.deepEqual(res.hard_invalid_reasons, []);
  // Nothing overdue, no DPO advice repeated, completed.iat < processing_start_at
  assert.deepEqual(res.warnings, []);
  assert.equal(res.iss_inconsistent, false);
  assert.equal(res.air_receipt_id_inconsistent, false);
  assert.equal(res.chain_head_not_threshold_triggered, false);
  assert.equal(res.predecessor_id, null);
});

test("walker: terminated chain accepted (no terminal-disposition mismatch issues)", () => {
  const t = r("t", thresholdTriggered());
  const tr = r("tr", terminated(), { prev: "t" });
  const idx = buildAirChainIndex([t, tr]);
  const res = walkAirChain("tr", idx);
  assert.equal(res.head?.id, "t");
  assert.deepEqual(res.hard_invalid_reasons, []);
});

// ── Index dedup ─────────────────────────────────────────────────────────────

test("buildAirChainIndex: duplicate IDs keep first occurrence", () => {
  const a = r("a", scopeLocked());
  const aPrime = r("a", completed());
  const idx = buildAirChainIndex([a, aPrime]);
  assert.equal(idx.byId.get("a")?.body.event_type, "dpia.scope_locked");
});
