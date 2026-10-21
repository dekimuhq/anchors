/**
 * Tests for the AQR v1 profile validators (spec §4.2 quality.output, §4.3 quality.release).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateQualityOutput,
  validateQualityOutputProfile,
  QUALITY_OUTPUT_PROFILE_ID,
} from "../src/output.ts";
import {
  validateQualityRelease,
  validateQualityReleaseProfile,
  QUALITY_RELEASE_PROFILE_ID,
} from "../src/release.ts";
import type { AQROutputBody, AQRReleaseBody, AQRBody } from "../src/body.ts";

const H = (c: string): string => `sha256:${c.repeat(64)}`;

function validOutput(): AQROutputBody {
  return {
    profile: "quality.output",
    suite_id: "regression-v3",
    suite_hash: H("a"),
    scorer: { kind: "deterministic" },
    result: {
      score: 0.95,
      verdict: "pass",
      threshold: 0.9,
      cases_total: 100,
      cases_passed: 95,
    },
    ran_at: "2026-06-19T10:00:00.000Z",
    output_commit: H("b"),
  };
}

function validRelease(): AQRReleaseBody {
  return {
    profile: "quality.release",
    suite_id: "release-gate",
    suite_hash: H("c"),
    scorer: { kind: "llm-judge", model: "claude-opus-4-8" },
    result: {
      score: 0.8,
      verdict: "warn",
      threshold: 0.85,
      cases_total: 50,
      cases_passed: 40,
    },
    ran_at: "2026-06-19T11:00:00.000Z",
    subject_ref: "agent@2.1.0",
    gate: "blocking",
  };
}

const errs = (b: AQRBody): string[] => validateQualityOutput(b).errors;
const rerrs = (b: AQRBody): string[] => validateQualityRelease(b).errors;
const has = (b: AQRBody, s: string): boolean => errs(b).includes(s);
const rhas = (b: AQRBody, s: string): boolean => rerrs(b).includes(s);

// ── quality.output happy path ──────────────────────────────────────────────

test("O1: valid output → no errors", () => {
  assert.deepEqual(validateQualityOutput(validOutput()).errors, []);
});

// ── common fields ──────────────────────────────────────────────────────────

test("O2: missing suite_id → suite_id_missing", () => {
  const b = { ...validOutput(), suite_id: "" };
  assert.ok(has(b, "quality.suite_id_missing"));
});

test("O3: malformed suite_hash → suite_hash_malformed", () => {
  const b = { ...validOutput(), suite_hash: "nope" };
  assert.ok(has(b, "quality.suite_hash_malformed"));
});

test("O4: suite_hash uppercase hex → suite_hash_malformed", () => {
  const b = { ...validOutput(), suite_hash: H("A") };
  assert.ok(has(b, "quality.suite_hash_malformed"));
});

test("O5: missing scorer → scorer_missing", () => {
  const b = { ...validOutput(), scorer: undefined } as unknown as AQRBody;
  assert.ok(has(b, "quality.scorer_missing"));
});

test("O6: invalid scorer.kind → scorer.kind_invalid", () => {
  const b = { ...validOutput(), scorer: { kind: "psychic" } } as unknown as AQRBody;
  assert.ok(has(b, "quality.scorer.kind_invalid"));
});

test("O7: llm-judge scorer without model → scorer.model_required", () => {
  const b = { ...validOutput(), scorer: { kind: "llm-judge" } } as unknown as AQRBody;
  assert.ok(has(b, "quality.scorer.model_required"));
});

test("O8: hybrid scorer without model → scorer.model_required", () => {
  const b = { ...validOutput(), scorer: { kind: "hybrid" } } as unknown as AQRBody;
  assert.ok(has(b, "quality.scorer.model_required"));
});

test("O9: llm-judge scorer with model → no model_required", () => {
  const b = { ...validOutput(), scorer: { kind: "llm-judge" as const, model: "claude-opus-4-8" } };
  assert.ok(!has(b, "quality.scorer.model_required"));
});

test("O10: deterministic scorer without model is fine", () => {
  assert.deepEqual(validateQualityOutput({ ...validOutput(), scorer: { kind: "deterministic" } }).errors, []);
});

test("O11: missing result → result_missing", () => {
  const b = { ...validOutput(), result: undefined } as unknown as AQRBody;
  assert.ok(has(b, "quality.result_missing"));
});

test("O12: score above 1 → result.score_range", () => {
  const b = { ...validOutput(), result: { ...validOutput().result, score: 1.5 } };
  assert.ok(has(b, "quality.result.score_range"));
});

test("O13: score below 0 → result.score_range", () => {
  const b = { ...validOutput(), result: { ...validOutput().result, score: -0.1 } };
  assert.ok(has(b, "quality.result.score_range"));
});

test("O14: threshold above 1 → result.threshold_range", () => {
  const b = { ...validOutput(), result: { ...validOutput().result, threshold: 2 } };
  assert.ok(has(b, "quality.result.threshold_range"));
});

test("O15: invalid verdict → result.verdict_invalid", () => {
  const b = { ...validOutput(), result: { ...validOutput().result, verdict: "maybe" } } as unknown as AQRBody;
  assert.ok(has(b, "quality.result.verdict_invalid"));
});

test("O16: non-integer cases_total → result.cases_total_invalid", () => {
  const b = { ...validOutput(), result: { ...validOutput().result, cases_total: 10.5 } };
  assert.ok(has(b, "quality.result.cases_total_invalid"));
});

test("O17: negative cases_total → result.cases_total_invalid", () => {
  const b = { ...validOutput(), result: { ...validOutput().result, cases_total: -1 } };
  assert.ok(has(b, "quality.result.cases_total_invalid"));
});

test("O18: cases_passed > cases_total → result.cases_passed_invalid", () => {
  const b = { ...validOutput(), result: { ...validOutput().result, cases_total: 10, cases_passed: 11 } };
  assert.ok(has(b, "quality.result.cases_passed_invalid"));
});

test("O19: negative cases_passed → result.cases_passed_invalid", () => {
  const b = { ...validOutput(), result: { ...validOutput().result, cases_passed: -1 } };
  assert.ok(has(b, "quality.result.cases_passed_invalid"));
});

test("O20: missing ran_at → ran_at_missing", () => {
  const b = { ...validOutput(), ran_at: "" };
  assert.ok(has(b, "quality.ran_at_missing"));
});

test("O21: malformed samples_commit → samples_commit_malformed", () => {
  const b = { ...validOutput(), samples_commit: "bad" };
  assert.ok(has(b, "quality.samples_commit_malformed"));
});

test("O22: valid samples_commit accepted", () => {
  assert.deepEqual(validateQualityOutput({ ...validOutput(), samples_commit: H("d") }).errors, []);
});

test("O23: malformed policy_hash → policy_hash_malformed", () => {
  const b = { ...validOutput(), policy_hash: "bad" };
  assert.ok(has(b, "quality.policy_hash_malformed"));
});

// ── quality.output-specific fields ─────────────────────────────────────────

test("O24: wrong profile → output.wrong_profile", () => {
  const b = { ...validOutput(), profile: "quality.release" } as unknown as AQRBody;
  assert.ok(has(b, "quality.output.wrong_profile"));
});

test("O25: missing output_commit → output.output_commit_missing", () => {
  const b = { ...validOutput(), output_commit: undefined } as unknown as AQRBody;
  assert.ok(has(b, "quality.output.output_commit_missing"));
});

test("O26: malformed output_commit → output.output_commit_malformed", () => {
  const b = { ...validOutput(), output_commit: "nope" };
  assert.ok(has(b, "quality.output.output_commit_malformed"));
});

test("O26b: present-but-non-sha256 output_commit → output.output_commit_malformed", () => {
  const b = { ...validOutput(), output_commit: "nope" };
  assert.ok(has(b, "quality.output.output_commit_malformed"));
  assert.ok(!has(b, "quality.output.output_commit_missing"));
});

test("O20b: malformed ran_at → ran_at_invalid", () => {
  const b = { ...validOutput(), ran_at: "yesterday" };
  assert.ok(has(b, "quality.ran_at_invalid"));
});

test("O20c: well-formed ran_at → no ran_at_* error", () => {
  const b = { ...validOutput(), ran_at: "2026-06-19T00:00:00Z" };
  const e = errs(b);
  assert.ok(!e.includes("quality.ran_at_missing"));
  assert.ok(!e.includes("quality.ran_at_invalid"));
});

test("O27: malformed request_id_commit → output.request_id_commit_malformed", () => {
  const b = { ...validOutput(), request_id_commit: "bad" };
  assert.ok(has(b, "quality.output.request_id_commit_malformed"));
});

test("O28: valid request_id_commit accepted", () => {
  assert.deepEqual(validateQualityOutput({ ...validOutput(), request_id_commit: H("e") }).errors, []);
});

test("O29: empty credential_id → output.credential_id_invalid", () => {
  const b = { ...validOutput(), credential_id: "" };
  assert.ok(has(b, "quality.output.credential_id_invalid"));
});

test("O30: caveats_consumed without credential_id → output.caveats_orphan", () => {
  const b = {
    ...validOutput(),
    caveats_consumed: { data_scope: "ws_1", spend_step: 1, capability: "x.y" },
  };
  assert.ok(has(b, "quality.output.caveats_orphan"));
});

test("O31: credential_id + caveats_consumed together accepted", () => {
  const b = {
    ...validOutput(),
    credential_id: "cred_123",
    caveats_consumed: { data_scope: "ws_1", spend_step: 1, capability: "x.y" },
  };
  assert.deepEqual(validateQualityOutput(b).errors, []);
});

test("O32: multiple errors collected", () => {
  const b = { profile: "quality.output", suite_id: "", suite_hash: "x" } as unknown as AQRBody;
  assert.ok(errs(b).length >= 3);
});

test("O33: profile id constant + adapter ok=true", () => {
  assert.equal(QUALITY_OUTPUT_PROFILE_ID, "quality.output");
  const r = validateQualityOutputProfile(null as never, validOutput(), {} as never);
  assert.equal(r.profile_id, "quality.output");
  assert.equal(r.ok, true);
  assert.equal("reason" in r, false);
});

test("O34: adapter ok=false + reason for invalid body", () => {
  const r = validateQualityOutputProfile(null as never, { ...validOutput(), output_commit: "x" }, {} as never);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "quality.output.output_commit_malformed");
});

// ── quality.release ────────────────────────────────────────────────────────

test("R1: valid release → no errors", () => {
  assert.deepEqual(validateQualityRelease(validRelease()).errors, []);
});

test("R2: wrong profile → release.wrong_profile", () => {
  const b = { ...validRelease(), profile: "quality.output" } as unknown as AQRBody;
  assert.ok(rhas(b, "quality.release.wrong_profile"));
});

test("R3: missing subject_ref → release.subject_ref_missing", () => {
  const b = { ...validRelease(), subject_ref: "" };
  assert.ok(rhas(b, "quality.release.subject_ref_missing"));
});

test("R4: invalid gate → release.gate_invalid", () => {
  const b = { ...validRelease(), gate: "soft" } as unknown as AQRBody;
  assert.ok(rhas(b, "quality.release.gate_invalid"));
});

test("R5: gate advisory accepted", () => {
  assert.deepEqual(validateQualityRelease({ ...validRelease(), gate: "advisory" }).errors, []);
});

test("R6: release also runs common validation (bad suite_hash)", () => {
  const b = { ...validRelease(), suite_hash: "nope" };
  assert.ok(rhas(b, "quality.suite_hash_malformed"));
});

test("R7: release llm-judge without model → scorer.model_required", () => {
  const b = { ...validRelease(), scorer: { kind: "llm-judge" } } as unknown as AQRBody;
  assert.ok(rhas(b, "quality.scorer.model_required"));
});

test("R8: profile id constant + adapter behaviour", () => {
  assert.equal(QUALITY_RELEASE_PROFILE_ID, "quality.release");
  const ok = validateQualityReleaseProfile(null as never, validRelease(), {} as never);
  assert.equal(ok.profile_id, "quality.release");
  assert.equal(ok.ok, true);
  assert.equal("reason" in ok, false);
  const bad = validateQualityReleaseProfile(null as never, { ...validRelease(), subject_ref: "" }, {} as never);
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, "quality.release.subject_ref_missing");
});
