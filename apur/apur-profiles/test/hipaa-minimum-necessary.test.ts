/**
 * Tests for the purpose.hipaa.minimum_necessary profile validator (APuR §5.4).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  HIPAA_MINIMUM_NECESSARY_PROFILE_ID,
  validateHipaaMinimumNecessary,
  validateHipaaMinimumNecessaryProfile,
} from "../src/hipaa-minimum-necessary.ts";

function validBinding(): Record<string, unknown> {
  return {
    event_type: "binding",
    activity_id_commit: "sha256:" + "aa".repeat(32),
    purpose_commit: "sha256:" + "bb".repeat(32),
    purpose_class: "hipaa:treatment",
    lawful_basis: "6(1)(c)",
    data_categories: ["hipaa:phi"],
    data_subjects_class: "customers",
    policy_hash: "sha256:" + "cc".repeat(32),
    minimisation_hash: "sha256:" + "dd".repeat(32),
    consent_receipt_hash: null,
    retention_receipt_hash: null,
    transfer_arrangement_hash: null,
    bound_at: "2026-05-16T10:00:00Z",
    covered_entity_commit: "sha256:" + "ee".repeat(32),
    workforce_role_class: "treating_physician",
  };
}

// ── Happy path ────────────────────────────────────────────────────────────────

test("hipaa-minimum-necessary: valid binding passes", () => {
  const out = validateHipaaMinimumNecessary(validBinding() as never);
  assert.deepEqual(out.errors, []);
});

// ── Wrong event type ──────────────────────────────────────────────────────────

test("hipaa-minimum-necessary: repurpose event produces wrong_event_type", () => {
  const body = { ...validBinding(), event_type: "repurpose" };
  const out = validateHipaaMinimumNecessary(body as never);
  assert.ok(out.errors.includes("purpose.hipaa.minimum_necessary.wrong_event_type"));
});

test("hipaa-minimum-necessary: unbinding event produces wrong_event_type", () => {
  const body = { ...validBinding(), event_type: "unbinding" };
  const out = validateHipaaMinimumNecessary(body as never);
  assert.ok(out.errors.includes("purpose.hipaa.minimum_necessary.wrong_event_type"));
});

test("hipaa-minimum-necessary: wrong_event_type short-circuits — only one error", () => {
  const body = { event_type: "repurpose" };
  const out = validateHipaaMinimumNecessary(body as never);
  assert.equal(out.errors.length, 1);
});

// ── covered_entity_commit ─────────────────────────────────────────────────────

test("hipaa-minimum-necessary: missing covered_entity_commit produces error", () => {
  const body = validBinding();
  delete body["covered_entity_commit"];
  const out = validateHipaaMinimumNecessary(body as never);
  assert.ok(out.errors.includes("purpose.hipaa.minimum_necessary.covered_entity_commit_missing"));
});

test("hipaa-minimum-necessary: empty covered_entity_commit produces error", () => {
  const body = { ...validBinding(), covered_entity_commit: "   " };
  const out = validateHipaaMinimumNecessary(body as never);
  assert.ok(out.errors.includes("purpose.hipaa.minimum_necessary.covered_entity_commit_missing"));
});

// ── workforce_role_class ──────────────────────────────────────────────────────

test("hipaa-minimum-necessary: missing workforce_role_class produces error", () => {
  const body = validBinding();
  delete body["workforce_role_class"];
  const out = validateHipaaMinimumNecessary(body as never);
  assert.ok(out.errors.includes("purpose.hipaa.minimum_necessary.workforce_role_class_missing"));
});

test("hipaa-minimum-necessary: empty workforce_role_class produces error", () => {
  const body = { ...validBinding(), workforce_role_class: "" };
  const out = validateHipaaMinimumNecessary(body as never);
  assert.ok(out.errors.includes("purpose.hipaa.minimum_necessary.workforce_role_class_missing"));
});

test("hipaa-minimum-necessary: both fields missing produces two errors", () => {
  const body = validBinding();
  delete body["covered_entity_commit"];
  delete body["workforce_role_class"];
  const out = validateHipaaMinimumNecessary(body as never);
  assert.equal(out.errors.length, 2);
});

// ── Adapter ───────────────────────────────────────────────────────────────────

test("hipaa-minimum-necessary adapter: ok=true on valid binding", () => {
  const out = validateHipaaMinimumNecessaryProfile(
    {} as never,
    validBinding() as never,
    {},
  );
  assert.equal(out.profile_id, HIPAA_MINIMUM_NECESSARY_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("hipaa-minimum-necessary adapter: ok=false with reason on missing commit", () => {
  const body = validBinding();
  delete body["covered_entity_commit"];
  const out = validateHipaaMinimumNecessaryProfile(
    {} as never,
    body as never,
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "purpose.hipaa.minimum_necessary.covered_entity_commit_missing",
  );
});
