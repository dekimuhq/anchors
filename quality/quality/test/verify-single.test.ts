/**
 * Tests for verifyQualityBody (AQR spec §5). SHAPE ONLY — provenance, not truth.
 * The verifier never re-derives quality or cross-checks verdict vs score.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyQualityBody } from "../src/verify-single.ts";

const SHA = "sha256:" + "a".repeat(64);
const SHA2 = "sha256:" + "b".repeat(64);

function validScorer(): Record<string, unknown> {
  return { kind: "deterministic" };
}
function validResult(): Record<string, unknown> {
  return { score: 0.9, threshold: 0.8, verdict: "pass", cases_total: 10, cases_passed: 9 };
}
function validOutputBody(): Record<string, unknown> {
  return {
    profile: "quality.output",
    suite_id: "suite-x",
    suite_hash: SHA,
    scorer: validScorer(),
    result: validResult(),
    ran_at: "2026-06-19T10:00:00Z",
    output_commit: SHA2,
  };
}
function validReleaseBody(): Record<string, unknown> {
  return {
    profile: "quality.release",
    suite_id: "suite-x",
    suite_hash: SHA,
    scorer: validScorer(),
    result: validResult(),
    ran_at: "2026-06-19T10:00:00Z",
    subject_ref: "version:1.2.3",
    gate: "blocking",
  };
}
function validCaveats(): Record<string, unknown> {
  return { data_scope: "clients", spend_step: 1, capability: "operator.score" };
}

function expectValid(body: unknown): void {
  const r = verifyQualityBody(body);
  assert.equal(r.valid, true, `expected valid, got: ${JSON.stringify(r.errors)}`);
  assert.deepEqual(r.errors, []);
  assert.notEqual(r.body, null);
}
function expectError(body: unknown, code: string): void {
  const r = verifyQualityBody(body);
  assert.equal(r.valid, false, `expected invalid for ${code}`);
  assert.ok(r.errors.includes(code), `expected error ${code}, got: ${JSON.stringify(r.errors)}`);
  assert.equal(r.body, null);
}
function expectNoError(body: unknown, code: string): void {
  const r = verifyQualityBody(body);
  assert.ok(!r.errors.includes(code), `did not expect error ${code}, got: ${JSON.stringify(r.errors)}`);
}

// ── happy paths ──────────────────────────────────────────────────────────────

test("valid quality.output body → valid", () => {
  expectValid(validOutputBody());
});

test("valid quality.release body → valid", () => {
  expectValid(validReleaseBody());
});

test("valid output body with all optionals → valid", () => {
  expectValid({
    ...validOutputBody(),
    samples_commit: SHA,
    policy_hash: SHA,
    policy_uri: "https://app.dekimu.com/evals",
    policy_version: "v1",
    request_id_commit: SHA2,
    credential_id: "cred-1",
    caveats_consumed: validCaveats(),
  });
});

// ── body shape ───────────────────────────────────────────────────────────────

test("null → body.not_object", () => {
  expectError(null, "body.not_object");
});
test("string → body.not_object", () => {
  expectError("nope", "body.not_object");
});
test("number → body.not_object", () => {
  expectError(42, "body.not_object");
});
test("array → body.not_object", () => {
  const r = verifyQualityBody([]);
  // arrays are objects; should not be body.not_object but will fail other checks
  assert.equal(r.valid, false);
});

// ── profile ──────────────────────────────────────────────────────────────────

test("bad profile string → profile.invalid", () => {
  expectError({ ...validOutputBody(), profile: "quality.unknown" }, "profile.invalid");
});
test("missing profile → profile.invalid", () => {
  const b = validOutputBody();
  delete b.profile;
  expectError(b, "profile.invalid");
});
test("non-string profile → profile.invalid", () => {
  expectError({ ...validOutputBody(), profile: 7 }, "profile.invalid");
});
test("quality.output profile → no profile.invalid", () => {
  expectNoError(validOutputBody(), "profile.invalid");
});

// ── suite_id ─────────────────────────────────────────────────────────────────

test("missing suite_id → suite_id.missing", () => {
  const b = validOutputBody();
  delete b.suite_id;
  expectError(b, "suite_id.missing");
});
test("empty suite_id → suite_id.missing", () => {
  expectError({ ...validOutputBody(), suite_id: "" }, "suite_id.missing");
});
test("present suite_id → no suite_id.missing", () => {
  expectNoError(validOutputBody(), "suite_id.missing");
});

// ── suite_hash ───────────────────────────────────────────────────────────────

test("missing suite_hash → suite_hash.invalid", () => {
  const b = validOutputBody();
  delete b.suite_hash;
  expectError(b, "suite_hash.invalid");
});
test("malformed suite_hash → suite_hash.invalid", () => {
  expectError({ ...validOutputBody(), suite_hash: "deadbeef" }, "suite_hash.invalid");
});
test("uppercase-hex suite_hash → suite_hash.invalid", () => {
  expectError({ ...validOutputBody(), suite_hash: "sha256:" + "A".repeat(64) }, "suite_hash.invalid");
});
test("valid suite_hash → no suite_hash.invalid", () => {
  expectNoError(validOutputBody(), "suite_hash.invalid");
});

// ── scorer ───────────────────────────────────────────────────────────────────

test("missing scorer → scorer.missing", () => {
  const b = validOutputBody();
  delete b.scorer;
  expectError(b, "scorer.missing");
});
test("null scorer → scorer.missing", () => {
  expectError({ ...validOutputBody(), scorer: null }, "scorer.missing");
});
test("scorer bad kind → scorer.kind_invalid", () => {
  expectError({ ...validOutputBody(), scorer: { kind: "magic" } }, "scorer.kind_invalid");
});
test("scorer human kind → no scorer.kind_invalid", () => {
  expectNoError({ ...validOutputBody(), scorer: { kind: "human" } }, "scorer.kind_invalid");
});
test("llm-judge scorer without model → scorer.model_required", () => {
  expectError({ ...validOutputBody(), scorer: { kind: "llm-judge" } }, "scorer.model_required");
});
test("hybrid scorer without model → scorer.model_required", () => {
  expectError({ ...validOutputBody(), scorer: { kind: "hybrid" } }, "scorer.model_required");
});
test("llm-judge scorer with model → no scorer.model_required", () => {
  expectNoError({ ...validOutputBody(), scorer: { kind: "llm-judge", model: "claude-opus-4-8" } }, "scorer.model_required");
});
test("deterministic scorer needs no model → no scorer.model_required", () => {
  expectNoError(validOutputBody(), "scorer.model_required");
});

// ── result ───────────────────────────────────────────────────────────────────

test("missing result → result.missing", () => {
  const b = validOutputBody();
  delete b.result;
  expectError(b, "result.missing");
});
test("null result → result.missing", () => {
  expectError({ ...validOutputBody(), result: null }, "result.missing");
});
test("score out of range (>1) → result.score_range", () => {
  expectError({ ...validOutputBody(), result: { ...validResult(), score: 1.5 } }, "result.score_range");
});
test("score out of range (<0) → result.score_range", () => {
  expectError({ ...validOutputBody(), result: { ...validResult(), score: -0.1 } }, "result.score_range");
});
test("score non-number → result.score_range", () => {
  expectError({ ...validOutputBody(), result: { ...validResult(), score: "high" } }, "result.score_range");
});
test("score in range → no result.score_range", () => {
  expectNoError(validOutputBody(), "result.score_range");
});
test("threshold out of range → result.threshold_range", () => {
  expectError({ ...validOutputBody(), result: { ...validResult(), threshold: 2 } }, "result.threshold_range");
});
test("threshold in range → no result.threshold_range", () => {
  expectNoError(validOutputBody(), "result.threshold_range");
});
test("bad verdict → result.verdict_invalid", () => {
  expectError({ ...validOutputBody(), result: { ...validResult(), verdict: "maybe" } }, "result.verdict_invalid");
});
test("warn verdict → no result.verdict_invalid", () => {
  expectNoError({ ...validOutputBody(), result: { ...validResult(), verdict: "warn" } }, "result.verdict_invalid");
});
test("non-int cases_total → result.cases_total_invalid", () => {
  expectError({ ...validOutputBody(), result: { ...validResult(), cases_total: 1.5 } }, "result.cases_total_invalid");
});
test("negative cases_total → result.cases_total_invalid", () => {
  expectError({ ...validOutputBody(), result: { ...validResult(), cases_total: -1 } }, "result.cases_total_invalid");
});
test("valid cases_total → no result.cases_total_invalid", () => {
  expectNoError(validOutputBody(), "result.cases_total_invalid");
});
test("cases_passed > cases_total → result.cases_passed_invalid", () => {
  expectError({ ...validOutputBody(), result: { ...validResult(), cases_total: 5, cases_passed: 9 } }, "result.cases_passed_invalid");
});
test("negative cases_passed → result.cases_passed_invalid", () => {
  expectError({ ...validOutputBody(), result: { ...validResult(), cases_passed: -1 } }, "result.cases_passed_invalid");
});
test("valid cases_passed → no result.cases_passed_invalid", () => {
  expectNoError(validOutputBody(), "result.cases_passed_invalid");
});

// ── ran_at (RFC-3339) ────────────────────────────────────────────────────────

test("missing ran_at → ran_at.missing", () => {
  const b = validOutputBody();
  delete b.ran_at;
  expectError(b, "ran_at.missing");
});
test("empty ran_at → ran_at.missing", () => {
  expectError({ ...validOutputBody(), ran_at: "" }, "ran_at.missing");
});
test("malformed ran_at (yesterday) → ran_at.invalid", () => {
  expectError({ ...validOutputBody(), ran_at: "yesterday" }, "ran_at.invalid");
});
test("ran_at wrong shape (date only) → ran_at.invalid", () => {
  expectError({ ...validOutputBody(), ran_at: "2026-06-19" }, "ran_at.invalid");
});
test("ran_at impossible date → ran_at.invalid", () => {
  expectError({ ...validOutputBody(), ran_at: "2026-13-40T99:99:99Z" }, "ran_at.invalid");
});
test("valid ran_at (Z) → no ran_at error", () => {
  expectNoError(validOutputBody(), "ran_at.invalid");
  expectNoError(validOutputBody(), "ran_at.missing");
});
test("valid ran_at (offset) → no ran_at.invalid", () => {
  expectNoError({ ...validOutputBody(), ran_at: "2026-06-19T10:00:00+02:00" }, "ran_at.invalid");
});

// ── optional commits ─────────────────────────────────────────────────────────

test("malformed samples_commit → samples_commit.invalid", () => {
  expectError({ ...validOutputBody(), samples_commit: "nope" }, "samples_commit.invalid");
});
test("absent samples_commit → no samples_commit.invalid", () => {
  expectNoError(validOutputBody(), "samples_commit.invalid");
});
test("malformed policy_hash → policy_hash.invalid", () => {
  expectError({ ...validOutputBody(), policy_hash: "nope" }, "policy_hash.invalid");
});
test("absent policy_hash → no policy_hash.invalid", () => {
  expectNoError(validOutputBody(), "policy_hash.invalid");
});

test("policy_uri / policy_version are unvalidated passthrough", () => {
  // arbitrary policy_uri/policy_version must not produce errors
  expectValid({ ...validOutputBody(), policy_uri: 12345 as unknown as string, policy_version: { x: 1 } as unknown as string });
});

// ── quality.output profile-specific ──────────────────────────────────────────

test("output missing output_commit → output_commit.missing", () => {
  const b = validOutputBody();
  delete b.output_commit;
  expectError(b, "output_commit.missing");
});
test("output malformed output_commit → output_commit.invalid", () => {
  expectError({ ...validOutputBody(), output_commit: "deadbeef" }, "output_commit.invalid");
});
test("output present output_commit → no output_commit error", () => {
  expectNoError(validOutputBody(), "output_commit.missing");
  expectNoError(validOutputBody(), "output_commit.invalid");
});
test("output malformed request_id_commit → request_id_commit.invalid", () => {
  expectError({ ...validOutputBody(), request_id_commit: "nope" }, "request_id_commit.invalid");
});
test("output empty credential_id → credential_id.invalid", () => {
  expectError({ ...validOutputBody(), credential_id: "" }, "credential_id.invalid");
});
test("output non-string credential_id → credential_id.invalid", () => {
  expectError({ ...validOutputBody(), credential_id: 5 }, "credential_id.invalid");
});
test("output malformed caveats_consumed → caveats_consumed.invalid", () => {
  expectError({ ...validOutputBody(), credential_id: "c1", caveats_consumed: { data_scope: "x" } }, "caveats_consumed.invalid");
});
test("output caveats without credential_id → caveats_consumed.orphan", () => {
  expectError({ ...validOutputBody(), caveats_consumed: validCaveats() }, "caveats_consumed.orphan");
});
test("output caveats with credential_id → no caveats_consumed.orphan", () => {
  expectNoError({ ...validOutputBody(), credential_id: "c1", caveats_consumed: validCaveats() }, "caveats_consumed.orphan");
});
test("output valid caveats with spend_currency → valid", () => {
  expectValid({ ...validOutputBody(), credential_id: "c1", caveats_consumed: { ...validCaveats(), spend_currency: "EUR" } });
});

// ── quality.release profile-specific ─────────────────────────────────────────

test("release missing subject_ref → subject_ref.missing", () => {
  const b = validReleaseBody();
  delete b.subject_ref;
  expectError(b, "subject_ref.missing");
});
test("release empty subject_ref → subject_ref.missing", () => {
  expectError({ ...validReleaseBody(), subject_ref: "" }, "subject_ref.missing");
});
test("release present subject_ref → no subject_ref.missing", () => {
  expectNoError(validReleaseBody(), "subject_ref.missing");
});
test("release missing gate → gate.invalid", () => {
  const b = validReleaseBody();
  delete b.gate;
  expectError(b, "gate.invalid");
});
test("release bad gate → gate.invalid", () => {
  expectError({ ...validReleaseBody(), gate: "soft" }, "gate.invalid");
});
test("release advisory gate → no gate.invalid", () => {
  expectNoError({ ...validReleaseBody(), gate: "advisory" }, "gate.invalid");
});
test("release does not require output_commit", () => {
  expectNoError(validReleaseBody(), "output_commit.missing");
});

// ── multi-error accumulation ─────────────────────────────────────────────────

test("multiple errors accumulate", () => {
  const r = verifyQualityBody({ profile: "bad", suite_id: "", suite_hash: "x" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.length >= 3);
});
