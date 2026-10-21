/**
 * Tests for the purpose.lgpd.art6 profile validator (APuR §5.5).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  LGPD_ART6_PROFILE_ID,
  validateLgpdArt6,
  validateLgpdArt6Profile,
} from "../src/lgpd-art6.ts";

function validBinding(): Record<string, unknown> {
  return {
    event_type: "binding",
    activity_id_commit: "sha256:" + "aa".repeat(32),
    purpose_commit: "sha256:" + "bb".repeat(32),
    purpose_class: "lgpd:legitimate_interest",
    lawful_basis: "6(1)(f)",
    data_categories: ["lgpd:personal_data"],
    data_subjects_class: "customers",
    policy_hash: "sha256:" + "cc".repeat(32),
    minimisation_hash: "sha256:" + "dd".repeat(32),
    consent_receipt_hash: null,
    retention_receipt_hash: null,
    transfer_arrangement_hash: null,
    bound_at: "2026-05-16T10:00:00Z",
  };
}

// ── Happy path ────────────────────────────────────────────────────────────────

test("lgpd-art6: valid binding passes", () => {
  const out = validateLgpdArt6(validBinding() as never);
  assert.deepEqual(out.errors, []);
});

// ── Wrong event type ──────────────────────────────────────────────────────────

test("lgpd-art6: repurpose event produces wrong_event_type", () => {
  const body = { ...validBinding(), event_type: "repurpose" };
  const out = validateLgpdArt6(body as never);
  assert.ok(out.errors.includes("purpose.lgpd.art6.wrong_event_type"));
});

test("lgpd-art6: unbinding event produces wrong_event_type", () => {
  const body = { ...validBinding(), event_type: "unbinding" };
  const out = validateLgpdArt6(body as never);
  assert.ok(out.errors.includes("purpose.lgpd.art6.wrong_event_type"));
});

test("lgpd-art6: wrong_event_type short-circuits — only one error", () => {
  const body = { event_type: "repurpose", purpose_class: "gdpr:something" };
  const out = validateLgpdArt6(body as never);
  assert.equal(out.errors.length, 1);
});

// ── purpose_class namespace ───────────────────────────────────────────────────

test("lgpd-art6: purpose_class without lgpd: prefix produces purpose_class_namespace", () => {
  const body = { ...validBinding(), purpose_class: "gdpr:6.1.a" };
  const out = validateLgpdArt6(body as never);
  assert.ok(out.errors.includes("purpose.lgpd.art6.purpose_class_namespace"));
});

test("lgpd-art6: missing purpose_class produces purpose_class_namespace", () => {
  const body = validBinding();
  delete body["purpose_class"];
  const out = validateLgpdArt6(body as never);
  assert.ok(out.errors.includes("purpose.lgpd.art6.purpose_class_namespace"));
});

test("lgpd-art6: non-string purpose_class produces purpose_class_namespace", () => {
  const body = { ...validBinding(), purpose_class: 42 };
  const out = validateLgpdArt6(body as never);
  assert.ok(out.errors.includes("purpose.lgpd.art6.purpose_class_namespace"));
});

// ── Adapter ───────────────────────────────────────────────────────────────────

test("lgpd-art6 adapter: ok=true on valid binding", () => {
  const out = validateLgpdArt6Profile({} as never, validBinding() as never, {});
  assert.equal(out.profile_id, LGPD_ART6_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("lgpd-art6 adapter: ok=false with reason on wrong namespace", () => {
  const body = { ...validBinding(), purpose_class: "hipaa:treatment" };
  const out = validateLgpdArt6Profile({} as never, body as never, {});
  assert.equal(out.ok, false);
  assert.equal(out.reason, "purpose.lgpd.art6.purpose_class_namespace");
});
