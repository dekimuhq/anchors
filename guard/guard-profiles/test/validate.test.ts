/**
 * Tests for the AGR v1 guard.input profile validator (spec §4.2).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { validateGuardInput } from "../src/validate.ts";

const H64 = "a".repeat(64);

function validBody() {
  return {
    profile: "guard.input",
    ruleset_id: "prompt-injection-v1",
    ruleset_hash: H64,
    ruleset_version: "1.0.0",
    content_commit: H64,
    decision: "blocked",
    matched_rules: [
      { id: "PI-001", category: "instruction_override", severity: "critical" },
    ],
    detector: { engine: "deterministic", name: "guard-detect", version: "0.1.0" },
    screened_at: "2026-06-20T10:00:00.000Z",
  };
}

// V1: valid body → ok === true
test("V1: valid body (blocked + one critical match) → ok true", () => {
  const r = validateGuardInput(validBody());
  assert.equal(r.ok, true);
  assert.deepEqual(r.errors, []);
});

// V2: decision "pass" with non-empty matched_rules → ok false
test("V2: pass decision with non-empty matched_rules → ok false", () => {
  const b = { ...validBody(), decision: "pass" };
  const r = validateGuardInput(b);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => e.includes("pass") && e.includes("matched_rules")));
});

// V3: decision "blocked" with empty matched_rules → ok false
test("V3: blocked decision with empty matched_rules → ok false", () => {
  const b = { ...validBody(), matched_rules: [] };
  const r = validateGuardInput(b);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => e.includes("non-pass") || e.includes("matched_rules")));
});

// V4: bad ruleset_hash → ok false
test("V4: bad ruleset_hash (xyz) → ok false", () => {
  const b = { ...validBody(), ruleset_hash: "xyz" };
  const r = validateGuardInput(b);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => e.includes("ruleset_hash")));
});

// V5: bad screened_at → ok false
test("V5: bad screened_at (not-a-date) → ok false", () => {
  const b = { ...validBody(), screened_at: "not-a-date" };
  const r = validateGuardInput(b);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => e.includes("screened_at")));
});

// V6: unknown category in a match → ok false
test("V6: unknown match category → ok false", () => {
  const b = {
    ...validBody(),
    matched_rules: [{ id: "X-001", category: "banana", severity: "critical" }],
  };
  const r = validateGuardInput(b);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => e.includes("category")));
});
