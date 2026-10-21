/**
 * Tests for the purpose.gdpr.art5 profile validator (APuR §5.1).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GDPR_ART5_PROFILE_ID,
  validateGdprArt5,
  validateGdprArt5Profile,
} from "../src/gdpr-art5.ts";

function validBinding(): Record<string, unknown> {
  return {
    event_type: "binding",
    activity_id_commit: "sha256:" + "aa".repeat(32),
    purpose_commit: "sha256:" + "bb".repeat(32),
    purpose_class: "gdpr:6.1.a",
    lawful_basis: "6(1)(a)",
    data_categories: ["gdpr:contact"],
    data_subjects_class: "customers",
    policy_hash: "sha256:" + "cc".repeat(32),
    minimisation_hash: "sha256:" + "dd".repeat(32),
    consent_receipt_hash: null,
    retention_receipt_hash: null,
    transfer_arrangement_hash: null,
    bound_at: "2026-05-16T10:00:00Z",
  };
}

function validUnbinding(): Record<string, unknown> {
  return {
    event_type: "unbinding",
    reason: "purpose_fulfilled",
    downstream_arr_receipt_hash: null,
    unbound_at: "2026-06-01T10:00:00Z",
  };
}

// ── Happy paths ───────────────────────────────────────────────────────────────

test("gdpr-art5: valid binding passes", () => {
  const out = validateGdprArt5(validBinding() as never);
  assert.deepEqual(out.errors, []);
});

test("gdpr-art5: valid unbinding passes", () => {
  const out = validateGdprArt5(validUnbinding() as never);
  assert.deepEqual(out.errors, []);
});

// ── Wrong event type ──────────────────────────────────────────────────────────

test("gdpr-art5: repurpose event produces wrong_event_type", () => {
  const body = { ...validBinding(), event_type: "repurpose" };
  const out = validateGdprArt5(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art5.wrong_event_type"));
});

test("gdpr-art5: wrong_event_type is the only error returned for repurpose", () => {
  // Even with bad fields, wrong_event_type short-circuits
  const body = {
    event_type: "repurpose",
    lawful_basis: "INVALID",
    data_categories: [],
  };
  const out = validateGdprArt5(body as never);
  assert.equal(out.errors.length, 1);
  assert.ok(out.errors.includes("purpose.gdpr.art5.wrong_event_type"));
});

// ── lawful_basis ──────────────────────────────────────────────────────────────

test("gdpr-art5: unknown lawful_basis produces lawful_basis_invalid", () => {
  const body = { ...validBinding(), lawful_basis: "5(1)(a)" };
  const out = validateGdprArt5(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art5.lawful_basis_invalid"));
});

test("gdpr-art5: missing lawful_basis produces lawful_basis_invalid", () => {
  const body = validBinding();
  delete body["lawful_basis"];
  const out = validateGdprArt5(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art5.lawful_basis_invalid"));
});

test("gdpr-art5: all six lawful_basis values pass", () => {
  const bases = ["6(1)(a)", "6(1)(b)", "6(1)(c)", "6(1)(d)", "6(1)(e)", "6(1)(f)"];
  for (const lb of bases) {
    const out = validateGdprArt5({ ...validBinding(), lawful_basis: lb } as never);
    assert.equal(
      out.errors.filter((e) => e === "purpose.gdpr.art5.lawful_basis_invalid").length,
      0,
      `basis ${lb} should pass`,
    );
  }
});

// ── data_categories ───────────────────────────────────────────────────────────

test("gdpr-art5: empty data_categories produces data_categories_empty", () => {
  const body = { ...validBinding(), data_categories: [] };
  const out = validateGdprArt5(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art5.data_categories_empty"));
});

test("gdpr-art5: missing data_categories produces data_categories_empty", () => {
  const body = validBinding();
  delete body["data_categories"];
  const out = validateGdprArt5(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art5.data_categories_empty"));
});

// ── data_subjects_class ───────────────────────────────────────────────────────

test("gdpr-art5: unknown data_subjects_class produces data_subjects_class_unknown", () => {
  const body = { ...validBinding(), data_subjects_class: "robots" };
  const out = validateGdprArt5(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art5.data_subjects_class_unknown"));
});

test("gdpr-art5: missing data_subjects_class produces data_subjects_class_unknown", () => {
  const body = validBinding();
  delete body["data_subjects_class"];
  const out = validateGdprArt5(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art5.data_subjects_class_unknown"));
});

// ── purpose_class namespace ───────────────────────────────────────────────────

test("gdpr-art5: purpose_class without gdpr: prefix produces purpose_class_namespace", () => {
  const body = { ...validBinding(), purpose_class: "marketing:email" };
  const out = validateGdprArt5(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art5.purpose_class_namespace"));
});

test("gdpr-art5: missing purpose_class produces purpose_class_namespace", () => {
  const body = validBinding();
  delete body["purpose_class"];
  const out = validateGdprArt5(body as never);
  assert.ok(out.errors.includes("purpose.gdpr.art5.purpose_class_namespace"));
});

// ── Adapter ───────────────────────────────────────────────────────────────────

test("gdpr-art5 adapter: ok=true on valid binding", () => {
  const out = validateGdprArt5Profile({} as never, validBinding() as never, {});
  assert.equal(out.profile_id, GDPR_ART5_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr-art5 adapter: ok=false with reason on invalid body", () => {
  const body = { ...validBinding(), lawful_basis: "BAD" };
  const out = validateGdprArt5Profile({} as never, body as never, {});
  assert.equal(out.ok, false);
  assert.equal(out.reason, "purpose.gdpr.art5.lawful_basis_invalid");
});
