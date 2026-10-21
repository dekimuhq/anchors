/**
 * Tests for `composeAir` — Phase 4B Task 3 compose-warnings callback.
 *
 * Each warning gets a positive case (fires), a negative case (doesn't fire),
 * and a boundary case (threshold edge). Short-circuit + malformed-input
 * paths covered.
 *
 * The factory pipeline integration (does `airFamily.verifyReceipt` actually
 * surface these on `FamilyVerifyResult.warnings`?) is exercised by the
 * envelope's own pipeline tests. This file tests the callback in isolation
 * so warning-emission logic can be reasoned about independently.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { composeAir } from "../src/compose.ts";

const MS_PER_DAY = 86_400_000;
const AIR_MONTH_MS = MS_PER_DAY * 30;

function dpiaCompletedBody(overrides: Record<string, unknown> = {}) {
  return {
    event_type: "dpia.completed",
    dpia_artifact_hash: "sha256:" + "f".repeat(64),
    dpia_uri: "https://example.test/dpia",
    residual_risk_level: "low",
    // Default review window = 6 months from default iat (2026-01-01) →
    // 2026-07-01 — well within the 12-month strict threshold. Tests that
    // need to exercise the review-window check set review_due_at explicitly.
    review_due_at: "2026-07-01T00:00:00Z",
    aer_receipt_ids: ["envelope-aer-1"],
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    abr_receipt_id: null,
    ...overrides,
  };
}

function input(
  body: unknown,
  profile: string | undefined = "impact.art35_3_a_automated_decisions",
  iat: string = "2026-01-01T00:00:00Z",
) {
  const opts: { resolveKey: () => undefined; profile?: string } = {
    resolveKey: () => undefined,
  };
  if (profile !== undefined) opts.profile = profile;
  return {
    envelope: {
      id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      claim_type: "ar.impact.v1",
      body,
      subject: null,
      iat,
      iss: "did:web:example.test",
      prev: null,
    },
    opts,
  };
}

// ── short-circuit + malformed input ──────────────────────────────────────────

test("composeAir — non-dpia.completed event_type returns ok: true with no warnings", async () => {
  for (const event_type of [
    "dpia.threshold_triggered",
    "dpia.scope_locked",
    "dpia.dpo_advised",
    "dpia.stakeholders_consulted",
    "dpia.reviewed",
    "dpia.prior_consultation_initiated",
    "dpia.prior_consultation_resolved",
    "dpia.processing_authorised",
    "dpia.processing_blocked",
    "dpia.terminated",
  ]) {
    const r = await composeAir(input({ event_type }));
    assert.deepEqual(r, { ok: true }, `${event_type} MUST NOT emit warnings`);
  }
});

test("composeAir — null/undefined/non-object body returns ok: true silently", async () => {
  assert.deepEqual(await composeAir(input(undefined)), { ok: true });
  assert.deepEqual(await composeAir(input(null)), { ok: true });
  assert.deepEqual(await composeAir(input("not-an-object")), { ok: true });
});

// ── art35_3a_aer_link_missing ────────────────────────────────────────────────

test("composeAir — art35_3a + dpia.completed + empty aer_receipt_ids → art35_3a_aer_link_missing", async () => {
  for (const aer of [null, []]) {
    const body = dpiaCompletedBody({ aer_receipt_ids: aer });
    const r = await composeAir(input(body));
    assert.equal(r.ok, true);
    assert.ok(
      r.warnings?.includes("art35_3a_aer_link_missing"),
      `aer_receipt_ids = ${JSON.stringify(aer)} MUST emit warning`,
    );
  }
});

test("composeAir — art35_3a + dpia.completed + non-empty aer_receipt_ids → no warning", async () => {
  const body = dpiaCompletedBody({ aer_receipt_ids: ["aer-1", "aer-2"] });
  const r = await composeAir(input(body));
  assert.equal(r.ok, true);
  assert.equal(
    r.warnings?.includes("art35_3a_aer_link_missing"),
    undefined,
  );
});

test("composeAir — non-art35_3a profile + empty aer_receipt_ids → no AER warning", async () => {
  for (const profile of [
    "impact.art35_3_b_large_scale_special_categories",
    "impact.art35_3_c_public_monitoring",
    "impact.art35_4_dpa_list",
    "impact.voluntary",
  ]) {
    const body = dpiaCompletedBody({ aer_receipt_ids: null });
    const r = await composeAir(input(body, profile));
    assert.ok(
      !r.warnings?.includes("art35_3a_aer_link_missing"),
      `${profile} MUST NOT emit art35_3a_aer_link_missing (got ${JSON.stringify(r.warnings)})`,
    );
  }
});

// ── art35_3b_alr_link_missing ────────────────────────────────────────────────

test("composeAir — art35_3b + dpia.completed + empty alr_receipt_ids → art35_3b_alr_link_missing", async () => {
  for (const alr of [null, []]) {
    const body = dpiaCompletedBody({ alr_receipt_ids: alr });
    const r = await composeAir(
      input(body, "impact.art35_3_b_large_scale_special_categories"),
    );
    assert.equal(r.ok, true);
    assert.ok(
      r.warnings?.includes("art35_3b_alr_link_missing"),
      `alr_receipt_ids = ${JSON.stringify(alr)} MUST emit warning`,
    );
  }
});

test("composeAir — art35_3b + non-empty alr_receipt_ids → no warning", async () => {
  const body = dpiaCompletedBody({ alr_receipt_ids: ["alr-1"] });
  const r = await composeAir(
    input(body, "impact.art35_3_b_large_scale_special_categories"),
  );
  assert.equal(
    r.warnings?.includes("art35_3b_alr_link_missing"),
    undefined,
  );
});

// ── review_window_long (strict 12-month) ─────────────────────────────────────

test("composeAir — review window > 12mo on strict profiles → review_window_long", async () => {
  const iat = "2026-01-01T00:00:00Z";
  const iatMs = Date.parse(iat);
  // 13 months past iat — well over the 12 × 30-day threshold.
  const reviewDueAt = new Date(iatMs + 13 * AIR_MONTH_MS).toISOString();

  for (const profile of [
    "impact.art35_3_a_automated_decisions",
    "impact.art35_3_b_large_scale_special_categories",
    "impact.art35_3_c_public_monitoring",
    "impact.art35_4_dpa_list",
  ]) {
    const body = dpiaCompletedBody({
      review_due_at: reviewDueAt,
      aer_receipt_ids: ["aer-1"],
      alr_receipt_ids: ["alr-1"],
    });
    const r = await composeAir(input(body, profile, iat));
    assert.ok(
      r.warnings?.includes("review_window_long"),
      `${profile} MUST emit review_window_long at 13mo`,
    );
  }
});

test("composeAir — review window ≤ 12mo on strict profiles → no review_window_long", async () => {
  const iat = "2026-01-01T00:00:00Z";
  const iatMs = Date.parse(iat);
  // Exactly 12 months — strict `>` threshold means this MUST NOT fire.
  const reviewDueAt = new Date(iatMs + 12 * AIR_MONTH_MS).toISOString();
  const body = dpiaCompletedBody({
    review_due_at: reviewDueAt,
    aer_receipt_ids: ["aer-1"],
  });
  const r = await composeAir(
    input(body, "impact.art35_3_a_automated_decisions", iat),
  );
  assert.equal(r.warnings?.includes("review_window_long"), undefined);
});

// ── review_window_long_voluntary (36-month) ──────────────────────────────────

test("composeAir — voluntary + review window > 36mo → review_window_long_voluntary", async () => {
  const iat = "2026-01-01T00:00:00Z";
  const iatMs = Date.parse(iat);
  // 37 months — well over the 36 × 30-day threshold.
  const reviewDueAt = new Date(iatMs + 37 * AIR_MONTH_MS).toISOString();
  const body = dpiaCompletedBody({ review_due_at: reviewDueAt });
  const r = await composeAir(input(body, "impact.voluntary", iat));
  assert.ok(r.warnings?.includes("review_window_long_voluntary"));
  // MUST NOT emit the strict variant on the voluntary profile.
  assert.ok(!r.warnings?.includes("review_window_long"));
});

test("composeAir — voluntary + review window ≤ 36mo → no review_window_long_voluntary", async () => {
  const iat = "2026-01-01T00:00:00Z";
  const iatMs = Date.parse(iat);
  const reviewDueAt = new Date(iatMs + 36 * AIR_MONTH_MS).toISOString();
  const body = dpiaCompletedBody({ review_due_at: reviewDueAt });
  const r = await composeAir(input(body, "impact.voluntary", iat));
  assert.equal(
    r.warnings?.includes("review_window_long_voluntary"),
    undefined,
  );
});

// ── malformed iat / review_due_at silently skip the review-window check ─────

test("composeAir — malformed iat / review_due_at silently skips review-window check (no warning)", async () => {
  // Malformed iat
  let body = dpiaCompletedBody({
    review_due_at: "2030-01-01T00:00:00Z",
    aer_receipt_ids: ["aer-1"],
  });
  let r = await composeAir(
    input(body, "impact.art35_3_a_automated_decisions", "not-a-date"),
  );
  assert.equal(r.warnings?.includes("review_window_long"), undefined);

  // Malformed review_due_at
  body = dpiaCompletedBody({
    review_due_at: "not-a-date",
    aer_receipt_ids: ["aer-1"],
  });
  r = await composeAir(
    input(
      body,
      "impact.art35_3_a_automated_decisions",
      "2026-01-01T00:00:00Z",
    ),
  );
  assert.equal(r.warnings?.includes("review_window_long"), undefined);
});

// ── profile absent / null on envelope ────────────────────────────────────────

test("composeAir — opts.profile undefined → no profile-keyed warnings (silent skip)", async () => {
  const body = dpiaCompletedBody({ aer_receipt_ids: null, alr_receipt_ids: null });
  // Construct opts WITHOUT a profile field. The default in input() applies
  // art35_3a; bypass it by passing the input shape inline.
  const r = await composeAir({
    envelope: {
      id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      claim_type: "ar.impact.v1",
      body,
      subject: null,
      iat: "2026-01-01T00:00:00Z",
      iss: "did:web:example.test",
      prev: null,
    },
    opts: { resolveKey: () => undefined },
  });
  assert.equal(r.ok, true);
  assert.ok(
    !r.warnings?.includes("art35_3a_aer_link_missing"),
    `opts.profile undefined MUST skip profile-keyed warning silently (got ${JSON.stringify(r.warnings)})`,
  );
});

// ── multiple warnings on a single receipt ────────────────────────────────────

test("composeAir — art35_3a + missing AER + long review window → both warnings co-emit", async () => {
  const iat = "2026-01-01T00:00:00Z";
  const iatMs = Date.parse(iat);
  const reviewDueAt = new Date(iatMs + 18 * AIR_MONTH_MS).toISOString();
  const body = dpiaCompletedBody({
    review_due_at: reviewDueAt,
    aer_receipt_ids: null,
  });
  const r = await composeAir(
    input(body, "impact.art35_3_a_automated_decisions", iat),
  );
  assert.equal(r.ok, true);
  assert.ok(r.warnings?.includes("art35_3a_aer_link_missing"));
  assert.ok(r.warnings?.includes("review_window_long"));
  assert.equal(r.warnings?.length, 2);
});

// ── Phase 4B-2 chain-walk warnings ───────────────────────────────────────────
//
// Each test builds an in-memory chain (oldest → newest, then the receipt
// under verification last), wires a `resolveReceiptById` resolver over that
// corpus, and feeds the head into composeAir to assert which chain-walk
// warnings flow up.

const CONTROLLER = "did:web:example.test";

interface ChainStep {
  id: string;
  prev: string | null;
  iat: string;
  body: Record<string, unknown>;
}

function makeChainResolver(steps: readonly ChainStep[]) {
  const byId = new Map<string, ChainStep>();
  for (const s of steps) byId.set(s.id, s);
  return (id: string) => {
    const s = byId.get(id);
    if (s === undefined) return null;
    return {
      id: s.id,
      iss: CONTROLLER,
      iat: s.iat,
      prev: s.prev,
      body: s.body,
    };
  };
}

function airReceiptIdCommon() {
  return "air-receipt-1";
}

function chainHead(): ChainStep {
  return {
    id: "rcpt-head",
    prev: null,
    iat: "2025-01-01T00:00:00Z",
    body: {
      event_type: "dpia.threshold_triggered",
      air_receipt_id: airReceiptIdCommon(),
      processing_activity_id: "pa-1",
      processing_activity_hash: "sha256:" + "a".repeat(64),
      processing_start_at: "2025-01-15T00:00:00Z",
      dpia_artifact_hash: null,
      dpia_uri: null,
      residual_risk_level: null,
      review_due_at: null,
      aer_receipt_ids: null,
      atr_receipt_ids: null,
      alr_receipt_ids: null,
      apur_receipt_ids: null,
      scope_hash: null,
      dpo_did_or_email_commit: null,
      dpo_advice_hash: null,
      consultation_method: null,
      consultation_output_hash: null,
      review_outcome: null,
      review_evidence_hash: null,
      dpa_jurisdiction: null,
      submission_hash: null,
      dpa_advice_hash: null,
      dpa_did: null,
      controller_response_hash: null,
      terminal_disposition: null,
      termination_reason_hash: null,
      abr_receipt_id: null,
    },
  };
}

function chainCompletedStep(
  id: string,
  prev: string,
  iat: string,
  overrides: Record<string, unknown> = {},
): ChainStep {
  return {
    id,
    prev,
    iat,
    body: {
      ...dpiaCompletedBody({ aer_receipt_ids: ["aer-1"], alr_receipt_ids: ["alr-1"] }),
      air_receipt_id: airReceiptIdCommon(),
      processing_activity_id: "pa-1",
      ...overrides,
    },
  };
}

function inputWithResolver(
  headStep: ChainStep,
  resolver: (id: string) => unknown,
  profile: string | undefined = "impact.art35_3_a_automated_decisions",
  extraOpts: Record<string, unknown> = {},
) {
  const opts: Record<string, unknown> = {
    resolveKey: () => undefined,
    resolveReceiptById: resolver,
    ...extraOpts,
  };
  if (profile !== undefined) opts.profile = profile;
  return {
    envelope: {
      id: headStep.id,
      claim_type: "ar.impact.v1",
      body: headStep.body,
      subject: null,
      iat: headStep.iat,
      iss: CONTROLLER,
      prev: headStep.prev,
    },
    opts: opts as { resolveKey: () => undefined; profile?: string },
  };
}

test("composeAir — no resolveReceiptById → chain-walk warnings silently skipped", async () => {
  // Build a chain where the review window is overdue, but don't supply a
  // resolver. dpia_review_overdue MUST NOT fire because we have no corpus.
  const head = chainHead();
  const completed = chainCompletedStep("rcpt-c1", head.id, "2025-02-01T00:00:00Z", {
    review_due_at: "2025-03-01T00:00:00Z",
  });
  const r = await composeAir(
    input(
      completed.body,
      "impact.art35_3_a_automated_decisions",
      completed.iat,
    ),
  );
  assert.equal(r.ok, true);
  assert.ok(!r.warnings?.includes("dpia_review_overdue"));
});

test("composeAir — dpia_review_overdue fires when review_due_at < now and no dpia.reviewed follows", async () => {
  const head = chainHead();
  const completed = chainCompletedStep("rcpt-c1", head.id, "2025-02-01T00:00:00Z", {
    review_due_at: "2025-03-01T00:00:00Z",
  });
  const resolver = makeChainResolver([head, completed]);
  const r = await composeAir(
    inputWithResolver(
      completed,
      resolver,
      "impact.art35_3_a_automated_decisions",
      { tsaReferenceTime: new Date("2025-06-01T00:00:00Z") },
    ),
  );
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("dpia_review_overdue"),
    `expected dpia_review_overdue, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAir — dpia_review_overdue does NOT fire when a dpia.reviewed follows the completed", async () => {
  const head = chainHead();
  const completed = chainCompletedStep("rcpt-c1", head.id, "2025-02-01T00:00:00Z", {
    review_due_at: "2025-03-01T00:00:00Z",
  });
  const reviewed: ChainStep = {
    id: "rcpt-r1",
    prev: completed.id,
    iat: "2025-02-15T00:00:00Z",
    body: {
      event_type: "dpia.reviewed",
      air_receipt_id: airReceiptIdCommon(),
      processing_activity_id: "pa-1",
      review_outcome: "no_material_change",
    },
  };
  const resolver = makeChainResolver([head, completed, reviewed]);
  const r = await composeAir(
    inputWithResolver(
      reviewed,
      resolver,
      "impact.art35_3_a_automated_decisions",
      { tsaReferenceTime: new Date("2025-06-01T00:00:00Z") },
    ),
  );
  assert.equal(r.ok, true);
  assert.ok(!r.warnings?.includes("dpia_review_overdue"));
});

test("composeAir — dpo_commit_drift fires when two dpo_advised events disagree", async () => {
  const head = chainHead();
  const advised1: ChainStep = {
    id: "rcpt-dpo1",
    prev: head.id,
    iat: "2025-01-05T00:00:00Z",
    body: {
      event_type: "dpia.dpo_advised",
      air_receipt_id: airReceiptIdCommon(),
      processing_activity_id: "pa-1",
      dpo_did_or_email_commit: "sha256:" + "a".repeat(64),
    },
  };
  const advised2: ChainStep = {
    id: "rcpt-dpo2",
    prev: advised1.id,
    iat: "2025-01-06T00:00:00Z",
    body: {
      event_type: "dpia.dpo_advised",
      air_receipt_id: airReceiptIdCommon(),
      processing_activity_id: "pa-1",
      dpo_did_or_email_commit: "sha256:" + "b".repeat(64),
    },
  };
  const resolver = makeChainResolver([head, advised1, advised2]);
  const r = await composeAir(
    inputWithResolver(
      advised2,
      resolver,
      "impact.art35_3_a_automated_decisions",
    ),
  );
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("dpo_commit_drift"),
    `expected dpo_commit_drift, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAir — dpia_post_hoc_warning fires when completed.iat > head.processing_start_at", async () => {
  const head = chainHead();
  // head.processing_start_at is 2025-01-15; completed lands 2025-02-01.
  const completed = chainCompletedStep("rcpt-c1", head.id, "2025-02-01T00:00:00Z", {
    review_due_at: "2026-01-01T00:00:00Z",
  });
  const resolver = makeChainResolver([head, completed]);
  const r = await composeAir(
    inputWithResolver(
      completed,
      resolver,
      "impact.art35_3_a_automated_decisions",
    ),
  );
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("dpia_post_hoc_warning"),
    `expected dpia_post_hoc_warning, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAir — dpia_post_hoc_warning does NOT fire when completed.iat < head.processing_start_at", async () => {
  const head = chainHead();
  // head.processing_start_at is 2025-01-15; completed lands 2025-01-10 (before).
  const completed = chainCompletedStep("rcpt-c1", head.id, "2025-01-10T00:00:00Z", {
    review_due_at: "2026-01-01T00:00:00Z",
  });
  const resolver = makeChainResolver([head, completed]);
  const r = await composeAir(
    inputWithResolver(
      completed,
      resolver,
      "impact.art35_3_a_automated_decisions",
    ),
  );
  assert.ok(!r.warnings?.includes("dpia_post_hoc_warning"));
});

test("composeAir — voluntary_high_risk_no_consultation fires on impact.voluntary + high-risk completed + no consultation", async () => {
  const head = chainHead();
  const completed = chainCompletedStep("rcpt-c1", head.id, "2025-01-10T00:00:00Z", {
    residual_risk_level: "high",
    review_due_at: "2026-01-01T00:00:00Z",
  });
  const resolver = makeChainResolver([head, completed]);
  const r = await composeAir(
    inputWithResolver(completed, resolver, "impact.voluntary"),
  );
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("voluntary_high_risk_no_consultation"),
    `expected voluntary_high_risk_no_consultation, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAir — voluntary_high_risk_no_consultation does NOT fire when prior_consultation_initiated follows", async () => {
  const head = chainHead();
  const completed = chainCompletedStep("rcpt-c1", head.id, "2025-01-10T00:00:00Z", {
    residual_risk_level: "high",
    review_due_at: "2026-01-01T00:00:00Z",
  });
  const initiated: ChainStep = {
    id: "rcpt-init",
    prev: completed.id,
    iat: "2025-01-20T00:00:00Z",
    body: {
      event_type: "dpia.prior_consultation_initiated",
      air_receipt_id: airReceiptIdCommon(),
      processing_activity_id: "pa-1",
    },
  };
  const resolver = makeChainResolver([head, completed, initiated]);
  const r = await composeAir(
    inputWithResolver(initiated, resolver, "impact.voluntary"),
  );
  assert.ok(!r.warnings?.includes("voluntary_high_risk_no_consultation"));
});

test("composeAir — voluntary_high_risk_no_consultation does NOT fire on non-voluntary profile", async () => {
  const head = chainHead();
  const completed = chainCompletedStep("rcpt-c1", head.id, "2025-01-10T00:00:00Z", {
    residual_risk_level: "high",
    review_due_at: "2026-01-01T00:00:00Z",
  });
  const resolver = makeChainResolver([head, completed]);
  // Same chain but profile is strict-3-a, not voluntary.
  const r = await composeAir(
    inputWithResolver(
      completed,
      resolver,
      "impact.art35_3_a_automated_decisions",
    ),
  );
  assert.ok(!r.warnings?.includes("voluntary_high_risk_no_consultation"));
});

test("composeAir — voluntary_high_risk_no_consultation does NOT fire when residual risk is low/medium", async () => {
  const head = chainHead();
  for (const level of ["low", "medium"] as const) {
    const completed = chainCompletedStep("rcpt-c1", head.id, "2025-01-10T00:00:00Z", {
      residual_risk_level: level,
      review_due_at: "2026-01-01T00:00:00Z",
    });
    const resolver = makeChainResolver([head, completed]);
    const r = await composeAir(
      inputWithResolver(completed, resolver, "impact.voluntary"),
    );
    assert.ok(
      !r.warnings?.includes("voluntary_high_risk_no_consultation"),
      `level=${level} MUST NOT emit warning`,
    );
  }
});

test("composeAir — dangling prev (resolver returns null) → chain-walk aborts gracefully, single-receipt warnings preserved", async () => {
  const head = chainHead();
  // completed.prev points to head.id but resolver doesn't know about head.
  const completed = chainCompletedStep("rcpt-c1", "rcpt-missing", "2025-02-01T00:00:00Z", {
    aer_receipt_ids: null,
    review_due_at: "2026-01-01T00:00:00Z",
  });
  // Empty resolver — head not in corpus.
  const resolver = makeChainResolver([]);
  const r = await composeAir(
    inputWithResolver(
      completed,
      resolver,
      "impact.art35_3_a_automated_decisions",
    ),
  );
  assert.equal(r.ok, true);
  // Single-receipt warning still fires.
  assert.ok(r.warnings?.includes("art35_3a_aer_link_missing"));
  // Chain-walk warnings cannot fire (no chain accessible).
  assert.ok(!r.warnings?.includes("dpia_review_overdue"));
  assert.ok(!r.warnings?.includes("dpia_post_hoc_warning"));
});

test("composeAir — resolver throw → bubbles to compose_threw via envelope pipeline", async () => {
  // The compose callback itself does NOT catch resolver throws — the
  // envelope pipeline wraps any throw as compose_threw. We assert here
  // that composeAir propagates (does not swallow).
  const head = chainHead();
  const completed = chainCompletedStep("rcpt-c1", head.id, "2025-02-01T00:00:00Z");
  const thrower = () => {
    throw new Error("resolver-blew-up");
  };
  await assert.rejects(
    async () =>
      composeAir(
        inputWithResolver(
          completed,
          thrower,
          "impact.art35_3_a_automated_decisions",
        ),
      ),
    /resolver-blew-up/,
  );
});

// ── §8.1 ADM cross-family composition warnings ────────────────────────────
//
// When aer_receipt_ids is non-empty on art35_3_a AND a resolver is available,
// composeAir resolves each referenced AER receipt and validates it is an AER
// conformity receipt. Three advisory warnings: art35_3a_aer_unresolvable,
// art35_3a_aer_not_conformity, art35_3a_aer_expired.

function aerConformityEnvelope(overrides: Record<string, unknown> = {}) {
  return {
    id: "aer-conformity-1",
    claim_type: "ar.evaluation.v1",
    iss: "did:web:provider.test",
    iat: "2025-06-01T00:00:00Z",
    prev: null,
    body: {
      event_type: "conformity",
      profile: "aiact.art43.internal",
      system_id_commit: "sha256:" + "c".repeat(64),
      system_version: "1.0.0",
      model_id_commit: "sha256:" + "d".repeat(64),
      risk_class: "high",
      annex_iii_categories: ["biometrics"],
      assessment_route: "internal_control",
      notified_body_id: null,
      harmonized_standards: [],
      tech_doc_hash: "sha256:" + "e".repeat(64),
      tech_doc_arr_receipt_hash: null,
      risk_management_system_hash: "sha256:" + "f".repeat(64),
      data_governance_hash: "sha256:" + "1".repeat(64),
      fundamental_rights_hash: null,
      training_atr_arrangement_hash: null,
      training_apur_binding_hash: null,
      valid_from: "2025-06-01T00:00:00Z",
      valid_until: "2026-06-01T00:00:00Z",
      ...overrides,
    },
  };
}

function admInput(
  aerReceiptIds: string[],
  resolverMap: Record<string, unknown>,
  iat: string = "2026-01-01T00:00:00Z",
) {
  const body = dpiaCompletedBody({ aer_receipt_ids: aerReceiptIds });
  const resolver = (id: string) =>
    id in resolverMap ? resolverMap[id] : null;
  return {
    envelope: {
      id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      claim_type: "ar.impact.v1",
      body,
      subject: null,
      iat,
      iss: "did:web:example.test",
      prev: null,
    },
    opts: {
      resolveKey: () => undefined,
      resolveReceiptById: resolver,
      profile: "impact.art35_3_a_automated_decisions",
    },
  };
}

test("composeAir ADM — valid AER conformity receipt → no ADM warnings", async () => {
  const aer = aerConformityEnvelope();
  const r = await composeAir(admInput(["aer-1"], { "aer-1": aer }));
  assert.equal(r.ok, true);
  assert.ok(!r.warnings?.includes("art35_3a_aer_unresolvable"));
  assert.ok(!r.warnings?.includes("art35_3a_aer_not_conformity"));
  assert.ok(!r.warnings?.includes("art35_3a_aer_expired"));
});

test("composeAir ADM — unresolvable AER receipt → art35_3a_aer_unresolvable", async () => {
  const r = await composeAir(admInput(["aer-missing"], {}));
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("art35_3a_aer_unresolvable"),
    `expected art35_3a_aer_unresolvable, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAir ADM — wrong claim_type → art35_3a_aer_not_conformity", async () => {
  const wrongFamily = {
    id: "wrong-1",
    claim_type: "ar.provenance.v1",
    iss: "did:web:other.test",
    iat: "2025-06-01T00:00:00Z",
    prev: null,
    body: { event_type: "mint" },
  };
  const r = await composeAir(admInput(["aer-1"], { "aer-1": wrongFamily }));
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("art35_3a_aer_not_conformity"),
    `expected art35_3a_aer_not_conformity, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAir ADM — AER transparency (not conformity) → art35_3a_aer_not_conformity", async () => {
  const transparency = {
    id: "aer-t-1",
    claim_type: "ar.evaluation.v1",
    iss: "did:web:provider.test",
    iat: "2025-06-01T00:00:00Z",
    prev: null,
    body: {
      event_type: "transparency",
      profile: "aiact.art50.chatbot",
    },
  };
  const r = await composeAir(admInput(["aer-1"], { "aer-1": transparency }));
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("art35_3a_aer_not_conformity"),
    `expected art35_3a_aer_not_conformity for transparency, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAir ADM — expired AER conformity (valid_until < iat) → art35_3a_aer_expired", async () => {
  // AER valid_until = 2025-12-01, AIR iat = 2026-01-01 → expired.
  const aer = aerConformityEnvelope({ valid_until: "2025-12-01T00:00:00Z" });
  const r = await composeAir(admInput(["aer-1"], { "aer-1": aer }));
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("art35_3a_aer_expired"),
    `expected art35_3a_aer_expired, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAir ADM — AER conformity valid_until exactly at iat → no expiry warning", async () => {
  // valid_until === iat — not strictly before, so no warning.
  const aer = aerConformityEnvelope({ valid_until: "2026-01-01T00:00:00Z" });
  const r = await composeAir(admInput(["aer-1"], { "aer-1": aer }));
  assert.equal(r.ok, true);
  assert.ok(!r.warnings?.includes("art35_3a_aer_expired"));
});

test("composeAir ADM — AER conformity with null valid_until → no expiry warning", async () => {
  const aer = aerConformityEnvelope({ valid_until: null });
  const r = await composeAir(admInput(["aer-1"], { "aer-1": aer }));
  assert.equal(r.ok, true);
  assert.ok(!r.warnings?.includes("art35_3a_aer_expired"));
});

test("composeAir ADM — multiple AER refs, one bad → per-receipt warnings", async () => {
  const good = aerConformityEnvelope();
  const expired = aerConformityEnvelope({ valid_until: "2025-06-01T00:00:00Z" });
  const r = await composeAir(
    admInput(
      ["aer-good", "aer-missing", "aer-expired"],
      { "aer-good": good, "aer-expired": expired },
    ),
  );
  assert.equal(r.ok, true);
  // One good, one unresolvable, one expired.
  assert.ok(r.warnings?.includes("art35_3a_aer_unresolvable"));
  assert.ok(r.warnings?.includes("art35_3a_aer_expired"));
  assert.ok(!r.warnings?.includes("art35_3a_aer_not_conformity"));
  // art35_3a_aer_link_missing MUST NOT fire (array was non-empty).
  assert.ok(!r.warnings?.includes("art35_3a_aer_link_missing"));
});

test("composeAir ADM — no resolver → ADM check skipped, only link-presence fires", async () => {
  // Non-empty aer_receipt_ids but no resolveReceiptById → no ADM warnings.
  const body = dpiaCompletedBody({ aer_receipt_ids: ["aer-1"] });
  const r = await composeAir(input(body, "impact.art35_3_a_automated_decisions"));
  assert.equal(r.ok, true);
  assert.ok(!r.warnings?.includes("art35_3a_aer_unresolvable"));
  assert.ok(!r.warnings?.includes("art35_3a_aer_not_conformity"));
  assert.ok(!r.warnings?.includes("art35_3a_aer_expired"));
  // link-missing should NOT fire because the array is non-empty.
  assert.ok(!r.warnings?.includes("art35_3a_aer_link_missing"));
});

test("composeAir ADM — non-art35_3a profile → ADM check does not fire", async () => {
  // Even with resolver and aer_receipt_ids, other profiles skip ADM.
  const aer = aerConformityEnvelope({ valid_until: "2020-01-01T00:00:00Z" });
  const body = dpiaCompletedBody({ aer_receipt_ids: ["aer-1"] });
  const resolver = (id: string) => (id === "aer-1" ? aer : null);
  const r = await composeAir({
    envelope: {
      id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      claim_type: "ar.impact.v1",
      body,
      subject: null,
      iat: "2026-01-01T00:00:00Z",
      iss: "did:web:example.test",
      prev: null,
    },
    opts: {
      resolveKey: () => undefined,
      resolveReceiptById: resolver,
      profile: "impact.voluntary",
    },
  });
  assert.equal(r.ok, true);
  assert.ok(!r.warnings?.includes("art35_3a_aer_expired"));
  assert.ok(!r.warnings?.includes("art35_3a_aer_unresolvable"));
  assert.ok(!r.warnings?.includes("art35_3a_aer_not_conformity"));
});
