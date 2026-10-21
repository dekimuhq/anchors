/**
 * Tests for verifyGuardBody (AGR spec §5). SHAPE ONLY — provenance, not safety.
 * The verifier never re-derives guard decisions or safety conclusions.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyGuardBody } from "../src/verify-single.ts";

const HEX64 = "a".repeat(64);
const HEX64B = "b".repeat(64);

function validBody(): Record<string, unknown> {
  return {
    profile: "guard.input",
    ruleset_id: "ruleset-default",
    ruleset_hash: HEX64,
    ruleset_version: "v1.0.0",
    content_commit: HEX64B,
    decision: "pass",
    matched_rules: [],
    detector: { engine: "deterministic", name: "guard-engine", version: "1.0.0" },
    screened_at: "2026-06-20T10:00:00Z",
  };
}

function expectValid(body: unknown): void {
  const r = verifyGuardBody(body);
  assert.equal(r.valid, true, `expected valid, got: ${JSON.stringify(r.errors)}`);
  assert.deepEqual(r.errors, []);
  assert.notEqual(r.body, null);
}

function expectInvalid(body: unknown): void {
  const r = verifyGuardBody(body);
  assert.equal(r.valid, false, `expected invalid, got valid`);
  assert.equal(r.body, null, "body should be null on invalid");
}

// ── happy path ────────────────────────────────────────────────────────────────

test("valid guard.input body (pass, empty matched_rules) → valid", () => {
  expectValid(validBody());
});

test("valid guard.input body with flagged decision → valid", () => {
  expectValid({
    ...validBody(),
    decision: "flagged",
    matched_rules: [
      { id: "rule-1", category: "jailbreak_template", severity: "warn" },
    ],
  });
});

test("valid guard.input body with all optionals → valid", () => {
  expectValid({
    ...validBody(),
    content_media_type: "text/plain",
    credential_id: "cred-abc",
    caveats_consumed: { data_scope: "agent", spend_step: 1, capability: "operator.screen" },
  });
});

// ── bad ruleset_hash ──────────────────────────────────────────────────────────

test("malformed ruleset_hash → invalid/body_invalid", () => {
  const r = verifyGuardBody({ ...validBody(), ruleset_hash: "notahex" });
  assert.equal(r.valid, false, "expected invalid");
  assert.equal(r.body, null);
  assert.ok(r.errors.length > 0, "expected at least one error");
});

test("short ruleset_hash → invalid/body_invalid", () => {
  const r = verifyGuardBody({ ...validBody(), ruleset_hash: "abc123" });
  assert.equal(r.valid, false);
  assert.equal(r.body, null);
});

// ── unknown profile → invalid ────────────────────────────────────────────────

test("unknown profile 'guard.output' → invalid", () => {
  const r = verifyGuardBody({ ...validBody(), profile: "guard.output" });
  assert.equal(r.valid, false);
  assert.equal(r.body, null);
  assert.ok(r.errors.length > 0);
});

test("missing profile → invalid", () => {
  const b = { ...validBody() };
  delete (b as Record<string, unknown>).profile;
  const r = verifyGuardBody(b);
  assert.equal(r.valid, false);
  assert.equal(r.body, null);
});

// ── non-object → invalid ──────────────────────────────────────────────────────

test("null → invalid", () => {
  expectInvalid(null);
});

test("string → invalid", () => {
  expectInvalid("nope");
});

test("number → invalid", () => {
  expectInvalid(42);
});

// ── multi-error accumulation ──────────────────────────────────────────────────

test("multiple field errors accumulate", () => {
  const r = verifyGuardBody({
    profile: "guard.input",
    ruleset_id: "",
    ruleset_hash: "bad",
    ruleset_version: "",
    content_commit: "bad",
    decision: "invalid_decision",
    matched_rules: [],
    detector: { engine: "deterministic", name: "x", version: "1" },
    screened_at: "2026-06-20T10:00:00Z",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.length >= 3, `expected ≥3 errors, got ${r.errors.length}: ${JSON.stringify(r.errors)}`);
});
