/**
 * Tests for the purpose.gdpr.art6_4 profile validator (APuR §5.2).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GDPR_ART6_4_PROFILE_ID,
  validateGdprArt6_4,
  validateGdprArt6_4Profile,
} from "../src/gdpr-art6-4.ts";

function validRepurpose(): Record<string, unknown> {
  return {
    event_type: "repurpose",
    new_purpose_commit: "sha256:" + "aa".repeat(32),
    new_purpose_class: "gdpr:6.1.f",
    compat_link_hash: "sha256:" + "11".repeat(32),
    compat_context_hash: "sha256:" + "22".repeat(32),
    compat_subjects_reasonable_hash: "sha256:" + "33".repeat(32),
    compat_consequences_hash: "sha256:" + "44".repeat(32),
    compat_safeguards_hash: "sha256:" + "55".repeat(32),
    compat_conclusion: "compatible",
    minimisation_hash: "sha256:" + "66".repeat(32),
    tested_at: "2026-06-10T10:00:00Z",
  };
}

// ── Happy path ────────────────────────────────────────────────────────────────

test("gdpr-art6_4: valid repurpose passes", () => {
  const out = validateGdprArt6_4(validRepurpose() as never);
  assert.deepEqual(out.errors, []);
});

// ── Wrong event type ──────────────────────────────────────────────────────────

test("gdpr-art6_4: binding event produces wrong_event_type", () => {
  const body = { ...validRepurpose(), event_type: "binding" };
  const out = validateGdprArt6_4(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art6_4.wrong_event_type"));
});

test("gdpr-art6_4: unbinding event produces wrong_event_type", () => {
  const body = { ...validRepurpose(), event_type: "unbinding" };
  const out = validateGdprArt6_4(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art6_4.wrong_event_type"));
});

test("gdpr-art6_4: wrong_event_type short-circuits — only one error", () => {
  const body = { event_type: "binding" };
  const out = validateGdprArt6_4(body as never);
  assert.equal(out.errors.length, 1);
});

// ── new_purpose_class ─────────────────────────────────────────────────────────

test("gdpr-art6_4: missing new_purpose_class produces new_purpose_class_missing", () => {
  const body = validRepurpose();
  delete body["new_purpose_class"];
  const out = validateGdprArt6_4(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art6_4.new_purpose_class_missing"));
});

test("gdpr-art6_4: empty new_purpose_class produces new_purpose_class_missing", () => {
  const body = { ...validRepurpose(), new_purpose_class: "   " };
  const out = validateGdprArt6_4(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art6_4.new_purpose_class_missing"));
});

// ── compat hash fields ────────────────────────────────────────────────────────

test("gdpr-art6_4: invalid compat_link_hash produces compat_link_hash_invalid", () => {
  const body = { ...validRepurpose(), compat_link_hash: "not-a-hash" };
  const out = validateGdprArt6_4(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art6_4.compat_link_hash_invalid"));
});

test("gdpr-art6_4: invalid compat_context_hash produces compat_context_hash_invalid", () => {
  const body = { ...validRepurpose(), compat_context_hash: "abc123" };
  const out = validateGdprArt6_4(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art6_4.compat_context_hash_invalid"));
});

test("gdpr-art6_4: invalid compat_subjects_reasonable_hash produces field_invalid", () => {
  const body = { ...validRepurpose(), compat_subjects_reasonable_hash: "" };
  const out = validateGdprArt6_4(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art6_4.compat_subjects_reasonable_hash_invalid"));
});

test("gdpr-art6_4: invalid compat_consequences_hash produces field_invalid", () => {
  const body = { ...validRepurpose(), compat_consequences_hash: 42 };
  const out = validateGdprArt6_4(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art6_4.compat_consequences_hash_invalid"));
});

test("gdpr-art6_4: invalid compat_safeguards_hash produces field_invalid", () => {
  const body = { ...validRepurpose(), compat_safeguards_hash: null };
  const out = validateGdprArt6_4(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art6_4.compat_safeguards_hash_invalid"));
});

test("gdpr-art6_4: missing all compat hashes produces 5 errors", () => {
  const body: Record<string, unknown> = {
    event_type: "repurpose",
    new_purpose_class: "gdpr:6.1.f",
  };
  const out = validateGdprArt6_4(body as never);
  assert.equal(out.errors.filter((e) => e.endsWith("_invalid")).length, 5);
});

// ── Adapter ───────────────────────────────────────────────────────────────────

test("gdpr-art6_4 adapter: ok=true on valid repurpose", () => {
  const out = validateGdprArt6_4Profile({} as never, validRepurpose() as never, {});
  assert.equal(out.profile_id, GDPR_ART6_4_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr-art6_4 adapter: ok=false with reason on wrong event type", () => {
  const body = { ...validRepurpose(), event_type: "binding" };
  const out = validateGdprArt6_4Profile({} as never, body as never, {});
  assert.equal(out.ok, false);
  assert.equal(out.reason, "purpose.gdpr.art6_4.wrong_event_type");
});
