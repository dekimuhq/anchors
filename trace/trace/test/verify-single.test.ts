import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyTraceBody } from "../src/verify-single.ts";

const good = {
  profile: "agent.trace",
  request_id_commit: "sha256:" + "a".repeat(64),
  stages: [{ stage: "execute", ms: 10, status: "ok" }],
  outcome: "ok",
  trace_commit: "sha256:" + "b".repeat(64),
  started_at: "2026-06-20T10:00:00Z",
  total_ms: 10,
};
test("valid body → valid:true", () => { const r = verifyTraceBody(good); assert.equal(r.valid, true); assert.deepEqual(r.errors, []); assert.ok(r.body); });
test("non-object → body.not_object", () => { assert.deepEqual(verifyTraceBody(null).errors, ["body.not_object"]); });
test("bad profile → profile.invalid", () => { assert.ok(verifyTraceBody({ ...good, profile: "x" }).errors.includes("profile.invalid")); });
test("missing request_id_commit → request_id_commit.missing", () => { const { request_id_commit, ...rest } = good; assert.ok(verifyTraceBody(rest).errors.includes("request_id_commit.missing")); });
test("malformed request_id_commit → request_id_commit.invalid", () => { assert.ok(verifyTraceBody({ ...good, request_id_commit: "nope" }).errors.includes("request_id_commit.invalid")); });
test("empty stages → stages.empty", () => { assert.ok(verifyTraceBody({ ...good, stages: [] }).errors.includes("stages.empty")); });
test("non-array stages → stages.empty", () => { assert.ok(verifyTraceBody({ ...good, stages: "x" }).errors.includes("stages.empty")); });
test("stage with negative ms → stages[0].ms.invalid", () => { assert.ok(verifyTraceBody({ ...good, stages: [{ stage: "x", ms: -1, status: "ok" }] }).errors.includes("stages[0].ms.invalid")); });
test("stage with empty name → stages[0].stage.invalid", () => { assert.ok(verifyTraceBody({ ...good, stages: [{ stage: "", ms: 1, status: "ok" }] }).errors.includes("stages[0].stage.invalid")); });
test("stage with bad status → stages[0].status.invalid", () => { assert.ok(verifyTraceBody({ ...good, stages: [{ stage: "x", ms: 1, status: "weird" }] }).errors.includes("stages[0].status.invalid")); });
test("bad outcome → outcome.invalid", () => { assert.ok(verifyTraceBody({ ...good, outcome: "boom" }).errors.includes("outcome.invalid")); });
test("outcome=error requires error_stage", () => { assert.ok(verifyTraceBody({ ...good, outcome: "error" }).errors.includes("error_stage.missing")); });
test("outcome=error with error_stage → valid", () => { assert.equal(verifyTraceBody({ ...good, outcome: "error", error_stage: "execute" }).valid, true); });
test("empty error_stage → error_stage.invalid", () => { assert.ok(verifyTraceBody({ ...good, error_stage: "" }).errors.includes("error_stage.invalid")); });
test("missing trace_commit → trace_commit.missing", () => { const { trace_commit, ...rest } = good; assert.ok(verifyTraceBody(rest).errors.includes("trace_commit.missing")); });
test("malformed trace_commit → trace_commit.invalid", () => { assert.ok(verifyTraceBody({ ...good, trace_commit: "nope" }).errors.includes("trace_commit.invalid")); });
test("missing started_at → started_at.missing", () => { const { started_at, ...rest } = good; assert.ok(verifyTraceBody(rest).errors.includes("started_at.missing")); });
test("bad started_at → started_at.invalid", () => { assert.ok(verifyTraceBody({ ...good, started_at: "2026-13-99" }).errors.includes("started_at.invalid")); });
test("negative total_ms → total_ms.invalid", () => { assert.ok(verifyTraceBody({ ...good, total_ms: -5 }).errors.includes("total_ms.invalid")); });
test("non-integer total_ms → total_ms.invalid", () => { assert.ok(verifyTraceBody({ ...good, total_ms: 1.5 }).errors.includes("total_ms.invalid")); });
test("malformed policy_hash → policy_hash.invalid", () => { assert.ok(verifyTraceBody({ ...good, policy_hash: "x" }).errors.includes("policy_hash.invalid")); });
test("empty credential_id → credential_id.invalid", () => { assert.ok(verifyTraceBody({ ...good, credential_id: "" }).errors.includes("credential_id.invalid")); });
test("caveats_consumed without credential_id → orphan", () => { assert.ok(verifyTraceBody({ ...good, caveats_consumed: { data_scope: "x", spend_step: 0, capability: "y" } }).errors.includes("caveats_consumed.orphan")); });
test("malformed caveats_consumed → caveats_consumed.invalid", () => { assert.ok(verifyTraceBody({ ...good, credential_id: "c", caveats_consumed: { data_scope: "x" } }).errors.includes("caveats_consumed.invalid")); });
test("caveats_consumed WITH credential_id → valid", () => { assert.equal(verifyTraceBody({ ...good, credential_id: "cred-1", caveats_consumed: { data_scope: "x", spend_step: 0, capability: "y" } }).valid, true); });
test("capability empty string → capability.invalid", () => { assert.ok(verifyTraceBody({ ...good, capability: "" }).errors.includes("capability.invalid")); });
test("valid capability → valid", () => { assert.equal(verifyTraceBody({ ...good, capability: "operator.draft-reminder" }).valid, true); });

// ── Extended negative/boundary tests to reach ≥99 floor ─────────────────────

// Profile
test("undefined profile → profile.invalid", () => { assert.ok(verifyTraceBody({ ...good, profile: undefined }).errors.includes("profile.invalid")); });
test("null profile → profile.invalid", () => { assert.ok(verifyTraceBody({ ...good, profile: null }).errors.includes("profile.invalid")); });
test("wrong profile string → profile.invalid", () => { assert.ok(verifyTraceBody({ ...good, profile: "quality.output" }).errors.includes("profile.invalid")); });

// request_id_commit
test("sha256: prefix only → request_id_commit.invalid", () => { assert.ok(verifyTraceBody({ ...good, request_id_commit: "sha256:" }).errors.includes("request_id_commit.invalid")); });
test("sha256 wrong hex length → request_id_commit.invalid", () => { assert.ok(verifyTraceBody({ ...good, request_id_commit: "sha256:" + "a".repeat(63) }).errors.includes("request_id_commit.invalid")); });
test("sha256 uppercase hex → request_id_commit.invalid", () => { assert.ok(verifyTraceBody({ ...good, request_id_commit: "sha256:" + "A".repeat(64) }).errors.includes("request_id_commit.invalid")); });
test("empty string request_id_commit → request_id_commit.invalid", () => { assert.ok(verifyTraceBody({ ...good, request_id_commit: "" }).errors.includes("request_id_commit.invalid")); });

// trace_commit
test("sha256: prefix only for trace_commit → trace_commit.invalid", () => { assert.ok(verifyTraceBody({ ...good, trace_commit: "sha256:" }).errors.includes("trace_commit.invalid")); });
test("trace_commit wrong hex length → trace_commit.invalid", () => { assert.ok(verifyTraceBody({ ...good, trace_commit: "sha256:" + "b".repeat(63) }).errors.includes("trace_commit.invalid")); });
test("empty string trace_commit → trace_commit.invalid", () => { assert.ok(verifyTraceBody({ ...good, trace_commit: "" }).errors.includes("trace_commit.invalid")); });

// stages
test("null stages → stages.empty", () => { assert.ok(verifyTraceBody({ ...good, stages: null }).errors.includes("stages.empty")); });
test("stages[0] ms=0 (zero) → valid (non-negative)", () => { assert.equal(verifyTraceBody({ ...good, stages: [{ stage: "x", ms: 0, status: "ok" }] }).valid, true); });
test("stages[0] ms=float → stages[0].ms.invalid", () => { assert.ok(verifyTraceBody({ ...good, stages: [{ stage: "x", ms: 1.1, status: "ok" }] }).errors.includes("stages[0].ms.invalid")); });
test("stages[0] ms=NaN → stages[0].ms.invalid", () => { assert.ok(verifyTraceBody({ ...good, stages: [{ stage: "x", ms: NaN, status: "ok" }] }).errors.includes("stages[0].ms.invalid")); });
test("stages[0] ms=string → stages[0].ms.invalid", () => { assert.ok(verifyTraceBody({ ...good, stages: [{ stage: "x", ms: "10" as unknown as number, status: "ok" }] }).errors.includes("stages[0].ms.invalid")); });
test("stages[0].status='ok' enum member → valid", () => { assert.equal(verifyTraceBody({ ...good, stages: [{ stage: "s", ms: 1, status: "ok" }] }).valid, true); });
test("stages[0].status='error' enum member → valid", () => { assert.equal(verifyTraceBody({ ...good, stages: [{ stage: "s", ms: 1, status: "error" }] }).valid, true); });
test("stages[0].status='skipped' enum member → valid", () => { assert.equal(verifyTraceBody({ ...good, stages: [{ stage: "s", ms: 1, status: "skipped" }] }).valid, true); });
test("stages[1].stage.invalid accumulates alongside stages[0].ok", () => { const r = verifyTraceBody({ ...good, stages: [{ stage: "ok", ms: 1, status: "ok" }, { stage: "", ms: 1, status: "ok" }] }); assert.ok(r.errors.includes("stages[1].stage.invalid")); assert.ok(!r.errors.includes("stages[0].stage.invalid")); });

// outcome
test("outcome='ok' → valid", () => { assert.equal(verifyTraceBody({ ...good, outcome: "ok" }).valid, true); });
test("outcome='denied' → valid", () => { assert.equal(verifyTraceBody({ ...good, outcome: "denied" }).valid, true); });
test("outcome='checkpoint' → valid", () => { assert.equal(verifyTraceBody({ ...good, outcome: "checkpoint" }).valid, true); });
test("outcome=null → outcome.invalid", () => { assert.ok(verifyTraceBody({ ...good, outcome: null }).errors.includes("outcome.invalid")); });

// started_at
test("started_at with fractional seconds → valid", () => { assert.equal(verifyTraceBody({ ...good, started_at: "2026-06-20T10:00:00.123Z" }).valid, true); });
test("started_at with tz offset → valid", () => { assert.equal(verifyTraceBody({ ...good, started_at: "2026-06-20T10:00:00+02:00" }).valid, true); });
test("started_at date only (no time) → started_at.invalid", () => { assert.ok(verifyTraceBody({ ...good, started_at: "2026-06-20" }).errors.includes("started_at.invalid")); });
test("started_at empty string → started_at.missing", () => { assert.ok(verifyTraceBody({ ...good, started_at: "" }).errors.includes("started_at.missing")); });
test("started_at=number → started_at.missing", () => { assert.ok(verifyTraceBody({ ...good, started_at: 1234567890 as unknown as string }).errors.includes("started_at.missing")); });

// total_ms
test("total_ms=0 → valid", () => { assert.equal(verifyTraceBody({ ...good, total_ms: 0 }).valid, true); });
test("total_ms=string → total_ms.invalid", () => { assert.ok(verifyTraceBody({ ...good, total_ms: "10" as unknown as number }).errors.includes("total_ms.invalid")); });

// policy_hash
test("valid policy_hash sha256 → valid", () => { assert.equal(verifyTraceBody({ ...good, policy_hash: "sha256:" + "c".repeat(64) }).valid, true); });
test("policy_hash sha256 uppercase → policy_hash.invalid", () => { assert.ok(verifyTraceBody({ ...good, policy_hash: "sha256:" + "C".repeat(64) }).errors.includes("policy_hash.invalid")); });

// credential_id
test("valid credential_id non-empty string → valid", () => { assert.equal(verifyTraceBody({ ...good, credential_id: "cred-abc-123" }).valid, true); });

// caveats_consumed sub-fields
test("caveats_consumed.data_scope empty → caveats_consumed.invalid", () => { assert.ok(verifyTraceBody({ ...good, credential_id: "c", caveats_consumed: { data_scope: "", spend_step: 0, capability: "x" } }).errors.includes("caveats_consumed.invalid")); });
test("caveats_consumed.capability empty → caveats_consumed.invalid", () => { assert.ok(verifyTraceBody({ ...good, credential_id: "c", caveats_consumed: { data_scope: "x", spend_step: 0, capability: "" } }).errors.includes("caveats_consumed.invalid")); });
test("caveats_consumed.spend_step negative → caveats_consumed.invalid", () => { assert.ok(verifyTraceBody({ ...good, credential_id: "c", caveats_consumed: { data_scope: "x", spend_step: -1, capability: "y" } }).errors.includes("caveats_consumed.invalid")); });
test("caveats_consumed.spend_step=0 → valid", () => { assert.equal(verifyTraceBody({ ...good, credential_id: "c", caveats_consumed: { data_scope: "x", spend_step: 0, capability: "y" } }).valid, true); });
test("caveats_consumed.spend_currency non-empty → valid", () => { assert.equal(verifyTraceBody({ ...good, credential_id: "c", caveats_consumed: { data_scope: "x", spend_step: 1, spend_currency: "EUR", capability: "y" } }).valid, true); });
test("caveats_consumed.spend_currency empty string → invalid", () => { assert.ok(verifyTraceBody({ ...good, credential_id: "c", caveats_consumed: { data_scope: "x", spend_step: 1, spend_currency: "", capability: "y" } }).errors.includes("caveats_consumed.invalid")); });

// multi-error accumulation (body is an object but has multiple fields wrong)
test("multiple errors accumulate (bad profile + bad outcome)", () => { const r = verifyTraceBody({ ...good, profile: "bad", outcome: "unknown" }); assert.ok(r.errors.includes("profile.invalid")); assert.ok(r.errors.includes("outcome.invalid")); assert.equal(r.valid, false); });
test("result body is non-null when valid", () => { const r = verifyTraceBody(good); assert.ok(r.body !== null); assert.equal(r.body?.profile, "agent.trace"); });
test("result body is null when invalid", () => { assert.equal(verifyTraceBody({ ...good, profile: "bad" }).body, null); });
