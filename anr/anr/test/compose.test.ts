/**
 * Tests for `composeAnr` — Phase 4D compose-warnings callback.
 *
 * Mirrors `air/air-verifier/test/compose.test.ts` and
 * `abr/abr-verifier/test/compose.test.ts` in structure. Two warnings:
 *
 *   - W1 `lang_jurisdiction_mismatch` (single-receipt, no resolver) —
 *     positive, negative, boundary (no region subtag, M.49 numeric region,
 *     EU jurisdiction, case insensitivity), per-event-type cross-cut, and
 *     defensive on malformed body shape.
 *
 *   - W2 `base_unresolvable` (chain-walk, resolver-gated) — positive,
 *     negative (resolver hit), resolver-undefined silent skip, non-translated
 *     event silent skip, and resolver-throw bubble-up (envelope pipeline
 *     wraps as `compose_threw:<msg>`).
 *
 * The factory pipeline integration (does `anrFamily.verifyReceipt` actually
 * surface these on `FamilyVerifyResult.warnings`?) is exercised by the
 * envelope's own pipeline tests. This file tests the callback in isolation
 * so warning-emission logic can be reasoned about independently.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { composeAnr } from "../src/compose.ts";

const CONTROLLER = "did:web:example.test";

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
      claim_type: "ar.notice.v1",
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

test("composeAnr — null/undefined/non-object body returns ok: true silently", async () => {
  assert.deepEqual(await composeAnr(input(undefined)), { ok: true });
  assert.deepEqual(await composeAnr(input(null)), { ok: true });
  assert.deepEqual(await composeAnr(input("not-an-object")), { ok: true });
});

// ── W1 — lang_jurisdiction_mismatch (single-receipt) ────────────────────────

test("composeAnr — lang_jurisdiction_mismatch: matching region passes silently", async () => {
  const body = {
    event_type: "notice.presented",
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    jurisdiction: "GB",
  };
  assert.deepEqual(await composeAnr(input(body)), { ok: true });
});

test("composeAnr — lang_jurisdiction_mismatch fires on notice.presented when region mismatches jurisdiction", async () => {
  const body = {
    event_type: "notice.presented",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: "GB",
  };
  const r = await composeAnr(input(body));
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("lang_jurisdiction_mismatch"),
    `expected lang_jurisdiction_mismatch, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAnr — lang_jurisdiction_mismatch: lang_tag with no region subtag skips silently", async () => {
  const body = {
    event_type: "notice.presented",
    profile: "notice.art13.collected_direct",
    lang_tag: "de",
    jurisdiction: "GB",
  };
  assert.deepEqual(await composeAnr(input(body)), { ok: true });
});

test("composeAnr — lang_jurisdiction_mismatch fires on notice.re_presented mismatch", async () => {
  const body = {
    event_type: "notice.re_presented",
    profile: "notice.art13.collected_direct",
    lang_tag: "fr-FR",
    jurisdiction: "DE",
  };
  const r = await composeAnr(input(body));
  assert.ok(r.warnings?.includes("lang_jurisdiction_mismatch"));
});

test("composeAnr — lang_jurisdiction_mismatch fires on notice.acknowledged mismatch", async () => {
  const body = {
    event_type: "notice.acknowledged",
    profile: "notice.art13.collected_direct",
    lang_tag: "es-ES",
    jurisdiction: "DE",
  };
  const r = await composeAnr(input(body));
  assert.ok(r.warnings?.includes("lang_jurisdiction_mismatch"));
});

test("composeAnr — lang_jurisdiction_mismatch SILENT on notice.translated (spec §4.5 omits jurisdiction)", async () => {
  const body = {
    event_type: "notice.translated",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: null,
    base_anr_id: "rcpt-base",
  };
  // jurisdiction null + translated event → warning MUST NOT fire even
  // when a hypothetical comparison would mismatch.
  const r = await composeAnr(input(body));
  assert.ok(!r.warnings?.includes("lang_jurisdiction_mismatch"));
});

test("composeAnr — lang_jurisdiction_mismatch fires on notice.withdrawn mismatch", async () => {
  const body = {
    event_type: "notice.withdrawn",
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    jurisdiction: "DE",
    cessation_reason: "service shut down",
    supersedes_anr_id: null,
  };
  const r = await composeAnr(input(body));
  assert.ok(r.warnings?.includes("lang_jurisdiction_mismatch"));
});

test("composeAnr — lang_jurisdiction_mismatch SILENT on jurisdiction='EU' (region-level reservation)", async () => {
  const body = {
    event_type: "notice.presented",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: "EU",
  };
  // "EU" is a region-level reservation per spec line 113 — no single-
  // country mapping. Compose silently skips.
  assert.deepEqual(await composeAnr(input(body)), { ok: true });
});

test("composeAnr — lang_jurisdiction_mismatch: case-insensitive comparison (en-gb vs GB matches)", async () => {
  const body = {
    event_type: "notice.presented",
    profile: "notice.art13.collected_direct",
    lang_tag: "en-gb",
    jurisdiction: "GB",
  };
  assert.deepEqual(await composeAnr(input(body)), { ok: true });
});

test("composeAnr — lang_jurisdiction_mismatch: M.49 numeric region (es-419) skips silently", async () => {
  const body = {
    event_type: "notice.presented",
    profile: "notice.art13.collected_direct",
    lang_tag: "es-419",
    jurisdiction: "ES",
  };
  // 419 = UN M.49 Latin America/Caribbean — not comparable to alpha-2.
  assert.deepEqual(await composeAnr(input(body)), { ok: true });
});

test("composeAnr — lang_jurisdiction_mismatch: script subtag is skipped, region after script is read", async () => {
  const body = {
    event_type: "notice.presented",
    profile: "notice.art13.collected_direct",
    lang_tag: "zh-Hans-CN",
    jurisdiction: "GB",
  };
  // Hans is a script subtag (4-alpha) → skipped; CN is the region → mismatch.
  const r = await composeAnr(input(body));
  assert.ok(r.warnings?.includes("lang_jurisdiction_mismatch"));
});

// ── W2 — base_unresolvable (chain-walk) ─────────────────────────────────────

test("composeAnr — base_unresolvable: no resolveReceiptById → silently skipped", async () => {
  const body = {
    event_type: "notice.translated",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: null,
    base_anr_id: "rcpt-base",
  };
  assert.deepEqual(await composeAnr(input(body)), { ok: true });
});

test("composeAnr — base_unresolvable: resolver hits → no warning", async () => {
  const body = {
    event_type: "notice.translated",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: null,
    base_anr_id: "rcpt-base",
  };
  const resolver = (id: string) => {
    if (id === "rcpt-base") return { id: "rcpt-base", iss: CONTROLLER };
    return null;
  };
  assert.deepEqual(
    await composeAnr(input(body, "2026-01-01T00:00:00Z", null, resolver)),
    { ok: true },
  );
});

test("composeAnr — base_unresolvable: resolver returns null → fires", async () => {
  const body = {
    event_type: "notice.translated",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: null,
    base_anr_id: "rcpt-missing",
  };
  const resolver = () => null;
  const r = await composeAnr(input(body, "2026-01-01T00:00:00Z", null, resolver));
  assert.equal(r.ok, true);
  assert.ok(
    r.warnings?.includes("base_unresolvable"),
    `expected base_unresolvable, got ${JSON.stringify(r.warnings)}`,
  );
});

test("composeAnr — base_unresolvable: resolver returns undefined → fires", async () => {
  const body = {
    event_type: "notice.translated",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: null,
    base_anr_id: "rcpt-missing",
  };
  const resolver = () => undefined;
  const r = await composeAnr(input(body, "2026-01-01T00:00:00Z", null, resolver));
  assert.ok(r.warnings?.includes("base_unresolvable"));
});

test("composeAnr — base_unresolvable SILENT on non-translated events", async () => {
  const body = {
    event_type: "notice.presented",
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    jurisdiction: "GB",
    // base_anr_id is pinned `null` on `notice.presented` per spec/types,
    // but defensively pass a string and confirm compose skips silently
    // because event_type !== "notice.translated".
    base_anr_id: "rcpt-missing",
  };
  const resolver = () => null;
  const r = await composeAnr(input(body, "2026-01-01T00:00:00Z", null, resolver));
  assert.ok(!r.warnings?.includes("base_unresolvable"));
});

test("composeAnr — base_unresolvable SILENT on translated event with non-string base_anr_id (defensive)", async () => {
  const body = {
    event_type: "notice.translated",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: null,
    base_anr_id: null,
  };
  const resolver = () => null;
  // Body validator already enforces base_anr_id is a string on translated
  // events; compose is defensive and silently skips on type mismatch
  // rather than firing a misleading warning.
  const r = await composeAnr(input(body, "2026-01-01T00:00:00Z", null, resolver));
  assert.ok(!r.warnings?.includes("base_unresolvable"));
});

test("composeAnr — resolver throw bubbles up (envelope pipeline wraps as compose_threw)", async () => {
  const body = {
    event_type: "notice.translated",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: null,
    base_anr_id: "rcpt-base",
  };
  const thrower = () => {
    throw new Error("resolver-blew-up");
  };
  await assert.rejects(
    async () =>
      composeAnr(input(body, "2026-01-01T00:00:00Z", null, thrower)),
    /resolver-blew-up/,
  );
});

// ── cross-cut: signature_valid invariant ────────────────────────────────────

test("composeAnr — both warnings can coexist on a translated event with mismatch-via-resolver path", async () => {
  // W1 is by design SILENT on `notice.translated`. The decision-doc test
  // 13 was inconsistent with W1's translated-exclusion rule; we resolve
  // by following the more specific spec rule. Here we verify the
  // independence claim: translated+unresolvable fires only W2; presented
  // with mismatch fires only W1. Both can fire on independent receipts;
  // they never co-fire on the same receipt by design.
  const translated = {
    event_type: "notice.translated",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: null,
    base_anr_id: "rcpt-missing",
  };
  const resolver = () => null;
  const r1 = await composeAnr(
    input(translated, "2026-01-01T00:00:00Z", null, resolver),
  );
  assert.deepEqual(r1.warnings, ["base_unresolvable"]);

  const presented = {
    event_type: "notice.presented",
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    jurisdiction: "GB",
  };
  const r2 = await composeAnr(input(presented));
  assert.deepEqual(r2.warnings, ["lang_jurisdiction_mismatch"]);
});

test("composeAnr — ok:true always; compose never returns ok:false (informational-only)", async () => {
  // Sweep across every event_type with the worst-case warnings active.
  const cases = [
    {
      event_type: "notice.presented",
      profile: "notice.art13.collected_direct",
      lang_tag: "de-DE",
      jurisdiction: "GB",
    },
    {
      event_type: "notice.re_presented",
      profile: "notice.art13.collected_direct",
      lang_tag: "fr-FR",
      jurisdiction: "DE",
    },
    {
      event_type: "notice.acknowledged",
      profile: "notice.art13.collected_direct",
      lang_tag: "es-ES",
      jurisdiction: "DE",
    },
    {
      event_type: "notice.withdrawn",
      profile: "notice.art13.collected_direct",
      lang_tag: "en-GB",
      jurisdiction: "DE",
      cessation_reason: "service shut down",
      supersedes_anr_id: null,
    },
    {
      event_type: "notice.translated",
      profile: "notice.art13.collected_direct",
      lang_tag: "de-DE",
      jurisdiction: null,
      base_anr_id: "rcpt-missing",
    },
    {
      event_type: "notice.joint_controller_essence",
      profile: "notice.art26.joint_controller_essence",
      lang_tag: "de-DE",
      jurisdiction: "FR",
      joint_controllers: [],
    },
  ];
  const resolver = () => null;
  for (const body of cases) {
    const r = await composeAnr(
      input(body, "2026-01-01T00:00:00Z", null, resolver),
    );
    assert.equal(r.ok, true, `${body.event_type} compose MUST return ok:true`);
  }
});
