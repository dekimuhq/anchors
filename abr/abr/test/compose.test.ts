/**
 * Tests for `composeAbr` — Phase 4C Task 3 compose-warnings callback.
 *
 * Single-receipt warning (clock_skew_warning) covered with positive,
 * negative, and boundary cases. Chain-walk warning (notification_overdue)
 * covered across the GDPR Art 33 + NIS2 Art 23 (three phases) deadline
 * surface, with suppression by prior `breach.dpa_delayed`, dangling chain,
 * and resolver-absent paths.
 *
 * The factory pipeline integration (does `abrFamily.verifyReceipt` actually
 * surface these on `FamilyVerifyResult.warnings`?) is exercised by the
 * envelope's own pipeline tests. This file tests the callback in isolation
 * so warning-emission logic can be reasoned about independently. Mirrors
 * the structure of `air/air-verifier/test/compose.test.ts`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { composeAbr } from "../src/compose.ts";

const MS_PER_MINUTE = 60_000;
const MS_PER_HOUR = 60 * MS_PER_MINUTE;
const MS_PER_DAY = 24 * MS_PER_HOUR;

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

function input(
  body: unknown,
  iat: string = "2026-01-01T00:00:00Z",
  prev: string | null = null,
  resolver?: (id: string) => unknown,
) {
  const opts: Record<string, unknown> = { resolveKey: () => undefined };
  if (resolver !== undefined) opts.resolveReceiptById = resolver;
  return {
    envelope: {
      id: "rcpt-under-test",
      claim_type: "ar.breach.v1",
      body,
      subject: null,
      iat,
      iss: CONTROLLER,
      prev,
    },
    opts: opts as { resolveKey: () => undefined },
  };
}

// ── short-circuit + malformed input ─────────────────────────────────────────

test("composeAbr — null/undefined/non-object body returns ok: true silently", async () => {
  assert.deepEqual(await composeAbr(input(undefined)), { ok: true });
  assert.deepEqual(await composeAbr(input(null)), { ok: true });
  assert.deepEqual(await composeAbr(input("not-an-object")), { ok: true });
});

test("composeAbr — events that emit neither warning return ok with no warnings", async () => {
  for (const event_type of [
    "breach.assessed",
    "breach.dpa_delayed",
    "breach.subject_notified",
    "breach.subject_notification_exempted",
    "breach.contained",
    "breach.closed",
  ]) {
    const body = {
      event_type,
      profile: "breach.gdpr.art33",
      incident_correlation_id: "inc-1",
    };
    const r = await composeAbr(input(body));
    assert.deepEqual(r, { ok: true }, `${event_type} MUST NOT emit warnings`);
  }
});

// ── clock_skew_warning ──────────────────────────────────────────────────────

test("composeAbr — clock_skew_warning fires when |iat - detected_at| > 5min on breach.detected", async () => {
  const iat = "2026-01-01T12:00:00Z";
  // detected_at = iat + 6 minutes → over the 5-minute tolerance.
  const detectedAt = new Date(Date.parse(iat) + 6 * MS_PER_MINUTE).toISOString();
  const body = {
    event_type: "breach.detected",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    detected_at: detectedAt,
  };
  const r = await composeAbr(input(body, iat));
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("clock_skew_warning"),
    `expected clock_skew_warning, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAbr — clock_skew_warning fires symmetrically (detected_at earlier than iat)", async () => {
  const iat = "2026-01-01T12:00:00Z";
  // detected_at = iat - 10 minutes — also over tolerance, the other direction.
  const detectedAt = new Date(Date.parse(iat) - 10 * MS_PER_MINUTE).toISOString();
  const body = {
    event_type: "breach.detected",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    detected_at: detectedAt,
  };
  const r = await composeAbr(input(body, iat));
  assert.ok(r.warnings?.includes("clock_skew_warning"));
});

test("composeAbr — clock_skew_warning does NOT fire at exactly the 5-minute boundary (> threshold)", async () => {
  const iat = "2026-01-01T12:00:00Z";
  // Exactly 5 minutes — strict `>` threshold means this MUST NOT fire.
  const detectedAt = new Date(Date.parse(iat) + 5 * MS_PER_MINUTE).toISOString();
  const body = {
    event_type: "breach.detected",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    detected_at: detectedAt,
  };
  const r = await composeAbr(input(body, iat));
  assert.ok(!r.warnings?.includes("clock_skew_warning"));
});

test("composeAbr — clock_skew_warning silently skips on malformed iat or detected_at", async () => {
  // Malformed iat
  let body: Record<string, unknown> = {
    event_type: "breach.detected",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    detected_at: "2026-01-01T12:00:00Z",
  };
  let r = await composeAbr(input(body, "not-a-date"));
  assert.ok(!r.warnings?.includes("clock_skew_warning"));

  // Malformed detected_at
  body = {
    event_type: "breach.detected",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    detected_at: "not-a-date",
  };
  r = await composeAbr(input(body, "2026-01-01T12:00:00Z"));
  assert.ok(!r.warnings?.includes("clock_skew_warning"));
});

test("composeAbr — clock_skew_warning does NOT fire on non-breach.detected events", async () => {
  const iat = "2026-01-01T12:00:00Z";
  // Wide divergence between iat and a `detected_at`-shaped field; event_type
  // is wrong → no warning.
  const body = {
    event_type: "breach.assessed",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    detected_at: "2026-01-02T00:00:00Z", // bogus on this event_type; ignored
  };
  const r = await composeAbr(input(body, iat));
  assert.ok(!r.warnings?.includes("clock_skew_warning"));
});

// ── notification_overdue: resolver-absent ───────────────────────────────────

test("composeAbr — no resolveReceiptById → notification_overdue silently skipped", async () => {
  const body = {
    event_type: "breach.dpa_notified",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    notification_phase: null,
  };
  // Long elapsed time but no resolver → cannot determine.
  const r = await composeAbr(input(body, "2026-02-01T00:00:00Z"));
  assert.deepEqual(r, { ok: true });
});

// ── notification_overdue: GDPR Art. 33 (72h) ────────────────────────────────

test("composeAbr — GDPR Art. 33 + elapsed > 72h + no delay → notification_overdue", async () => {
  const detected: ChainStep = {
    id: "rcpt-detected",
    prev: null,
    iat: "2026-01-01T00:00:00Z",
    body: {
      event_type: "breach.detected",
      profile: "breach.gdpr.art33",
      incident_correlation_id: "inc-1",
      detected_at: "2026-01-01T00:00:00Z",
    },
  };
  const resolver = makeChainResolver([detected]);
  // Notified 73h after detected → over the 72h Art. 33 deadline.
  const notifiedIat = new Date(
    Date.parse(detected.iat) + 73 * MS_PER_HOUR,
  ).toISOString();
  const notifiedBody = {
    event_type: "breach.dpa_notified",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    notification_phase: null,
  };
  const r = await composeAbr(
    input(notifiedBody, notifiedIat, detected.id, resolver),
  );
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("notification_overdue"),
    `expected notification_overdue, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAbr — GDPR Art. 33 + elapsed ≤ 72h → no notification_overdue", async () => {
  const detected: ChainStep = {
    id: "rcpt-detected",
    prev: null,
    iat: "2026-01-01T00:00:00Z",
    body: {
      event_type: "breach.detected",
      profile: "breach.gdpr.art33",
      incident_correlation_id: "inc-1",
      detected_at: "2026-01-01T00:00:00Z",
    },
  };
  const resolver = makeChainResolver([detected]);
  // Exactly 72h — strict `>` threshold means this MUST NOT fire.
  const notifiedIat = new Date(
    Date.parse(detected.iat) + 72 * MS_PER_HOUR,
  ).toISOString();
  const notifiedBody = {
    event_type: "breach.dpa_notified",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    notification_phase: null,
  };
  const r = await composeAbr(
    input(notifiedBody, notifiedIat, detected.id, resolver),
  );
  assert.ok(!r.warnings?.includes("notification_overdue"));
});

// ── notification_overdue: suppression by breach.dpa_delayed ─────────────────

test("composeAbr — notification_overdue suppressed by prior breach.dpa_delayed", async () => {
  const detected: ChainStep = {
    id: "rcpt-detected",
    prev: null,
    iat: "2026-01-01T00:00:00Z",
    body: {
      event_type: "breach.detected",
      profile: "breach.gdpr.art33",
      incident_correlation_id: "inc-1",
      detected_at: "2026-01-01T00:00:00Z",
    },
  };
  const delayed: ChainStep = {
    id: "rcpt-delayed",
    prev: detected.id,
    iat: "2026-01-02T00:00:00Z",
    body: {
      event_type: "breach.dpa_delayed",
      profile: "breach.gdpr.art33",
      incident_correlation_id: "inc-1",
      delay_reason_hash: "sha256:" + "a".repeat(64),
      delay_until_at: "2026-01-10T00:00:00Z",
    },
  };
  const resolver = makeChainResolver([detected, delayed]);
  // Notified 5 days after detected — well over 72h, but suppressed.
  const notifiedIat = new Date(
    Date.parse(detected.iat) + 5 * MS_PER_DAY,
  ).toISOString();
  const notifiedBody = {
    event_type: "breach.dpa_notified",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    notification_phase: null,
  };
  const r = await composeAbr(
    input(notifiedBody, notifiedIat, delayed.id, resolver),
  );
  assert.ok(
    !r.warnings?.includes("notification_overdue"),
    `breach.dpa_delayed must suppress, got ${JSON.stringify(r.warnings)}`,
  );
});

// ── notification_overdue: NIS2 Art. 23 (24h/72h/30d) ────────────────────────

test("composeAbr — NIS2 early_warning + elapsed > 24h → notification_overdue", async () => {
  const detected: ChainStep = {
    id: "rcpt-detected",
    prev: null,
    iat: "2026-01-01T00:00:00Z",
    body: {
      event_type: "breach.detected",
      profile: "breach.nis2.art23",
      incident_correlation_id: "inc-1",
      detected_at: "2026-01-01T00:00:00Z",
    },
  };
  const resolver = makeChainResolver([detected]);
  // 25 hours after detected → over 24h early-warning deadline.
  const notifiedIat = new Date(
    Date.parse(detected.iat) + 25 * MS_PER_HOUR,
  ).toISOString();
  const notifiedBody = {
    event_type: "breach.dpa_notified",
    profile: "breach.nis2.art23",
    incident_correlation_id: "inc-1",
    notification_phase: "early_warning",
  };
  const r = await composeAbr(
    input(notifiedBody, notifiedIat, detected.id, resolver),
  );
  assert.ok(r.warnings?.includes("notification_overdue"));
});

test("composeAbr — NIS2 full_notification + elapsed > 72h → notification_overdue", async () => {
  const detected: ChainStep = {
    id: "rcpt-detected",
    prev: null,
    iat: "2026-01-01T00:00:00Z",
    body: {
      event_type: "breach.detected",
      profile: "breach.nis2.art23",
      incident_correlation_id: "inc-1",
      detected_at: "2026-01-01T00:00:00Z",
    },
  };
  const resolver = makeChainResolver([detected]);
  const notifiedIat = new Date(
    Date.parse(detected.iat) + 73 * MS_PER_HOUR,
  ).toISOString();
  const notifiedBody = {
    event_type: "breach.dpa_notified",
    profile: "breach.nis2.art23",
    incident_correlation_id: "inc-1",
    notification_phase: "full_notification",
  };
  const r = await composeAbr(
    input(notifiedBody, notifiedIat, detected.id, resolver),
  );
  assert.ok(r.warnings?.includes("notification_overdue"));
});

test("composeAbr — NIS2 final_report + elapsed > 30 days → notification_overdue", async () => {
  const detected: ChainStep = {
    id: "rcpt-detected",
    prev: null,
    iat: "2026-01-01T00:00:00Z",
    body: {
      event_type: "breach.detected",
      profile: "breach.nis2.art23",
      incident_correlation_id: "inc-1",
      detected_at: "2026-01-01T00:00:00Z",
    },
  };
  const resolver = makeChainResolver([detected]);
  const notifiedIat = new Date(
    Date.parse(detected.iat) + 31 * MS_PER_DAY,
  ).toISOString();
  const notifiedBody = {
    event_type: "breach.dpa_notified",
    profile: "breach.nis2.art23",
    incident_correlation_id: "inc-1",
    notification_phase: "final_report",
  };
  const r = await composeAbr(
    input(notifiedBody, notifiedIat, detected.id, resolver),
  );
  assert.ok(r.warnings?.includes("notification_overdue"));
});

test("composeAbr — NIS2 with null notification_phase silently skips (no deadline)", async () => {
  const detected: ChainStep = {
    id: "rcpt-detected",
    prev: null,
    iat: "2026-01-01T00:00:00Z",
    body: {
      event_type: "breach.detected",
      profile: "breach.nis2.art23",
      incident_correlation_id: "inc-1",
      detected_at: "2026-01-01T00:00:00Z",
    },
  };
  const resolver = makeChainResolver([detected]);
  const notifiedIat = new Date(
    Date.parse(detected.iat) + 60 * MS_PER_DAY,
  ).toISOString();
  // notification_phase: null on a NIS2 receipt — no deadline maps. Compose
  // skips silently rather than picking an arbitrary deadline.
  const notifiedBody = {
    event_type: "breach.dpa_notified",
    profile: "breach.nis2.art23",
    incident_correlation_id: "inc-1",
    notification_phase: null,
  };
  const r = await composeAbr(
    input(notifiedBody, notifiedIat, detected.id, resolver),
  );
  assert.ok(!r.warnings?.includes("notification_overdue"));
});

// ── notification_overdue: profiles without compose-side deadlines ───────────

test("composeAbr — Art 34 / DORA / US-AG profiles silently skip notification_overdue", async () => {
  for (const profile of [
    "breach.gdpr.art34",
    "breach.dora.art19",
    "breach.us_state.attorney_general",
  ]) {
    const detected: ChainStep = {
      id: "rcpt-detected",
      prev: null,
      iat: "2026-01-01T00:00:00Z",
      body: {
        event_type: "breach.detected",
        profile,
        incident_correlation_id: "inc-1",
        detected_at: "2026-01-01T00:00:00Z",
      },
    };
    const resolver = makeChainResolver([detected]);
    // Months past any plausible deadline.
    const notifiedIat = new Date(
      Date.parse(detected.iat) + 90 * MS_PER_DAY,
    ).toISOString();
    const notifiedBody = {
      event_type: "breach.dpa_notified",
      profile,
      incident_correlation_id: "inc-1",
      notification_phase: null,
    };
    const r = await composeAbr(
      input(notifiedBody, notifiedIat, detected.id, resolver),
    );
    assert.ok(
      !r.warnings?.includes("notification_overdue"),
      `${profile} MUST NOT emit notification_overdue (got ${JSON.stringify(r.warnings)})`,
    );
  }
});

// ── notification_overdue: dangling chain → silent skip ──────────────────────

test("composeAbr — dangling prev (resolver returns null) silently skips notification_overdue", async () => {
  // Empty resolver — the named `prev` is not in corpus.
  const resolver = makeChainResolver([]);
  const notifiedBody = {
    event_type: "breach.dpa_notified",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    notification_phase: null,
  };
  const r = await composeAbr(
    input(notifiedBody, "2026-02-01T00:00:00Z", "rcpt-missing", resolver),
  );
  assert.equal(r.ok, true);
  assert.ok(!r.warnings?.includes("notification_overdue"));
});

// ── resolver throw bubbles up ───────────────────────────────────────────────

test("composeAbr — resolver throw bubbles up (envelope pipeline wraps as compose_threw)", async () => {
  const thrower = () => {
    throw new Error("resolver-blew-up");
  };
  const notifiedBody = {
    event_type: "breach.dpa_notified",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "inc-1",
    notification_phase: null,
  };
  await assert.rejects(
    async () =>
      composeAbr(
        input(notifiedBody, "2026-02-01T00:00:00Z", "rcpt-prev", thrower),
      ),
    /resolver-blew-up/,
  );
});
