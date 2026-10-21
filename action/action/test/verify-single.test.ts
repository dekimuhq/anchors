/**
 * Tests for verifyActionBody (AActR structural body validation).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyActionBody } from "../src/verify-single.ts";
import { validBody, H } from "./_helpers/fixtures.ts";

test("B1: valid body passes", () => {
  const r = verifyActionBody(validBody());
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.ok(r.body);
});

test("B2: non-object input → body.not_object", () => {
  const r = verifyActionBody("nope");
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["body.not_object"]);
  assert.equal(r.body, null);
});

test("B3: null input → body.not_object", () => {
  const r = verifyActionBody(null);
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["body.not_object"]);
});

test("B4: array input → body.not_object is NOT raised (array is an object)", () => {
  // arrays are objects; field checks then fail instead
  const r = verifyActionBody([]);
  assert.equal(r.valid, false);
  assert.ok(!r.errors.includes("body.not_object"));
});

test("B5: missing profile → profile.invalid", () => {
  const b = validBody() as Record<string, unknown>;
  delete b.profile;
  assert.ok(verifyActionBody(b).errors.includes("profile.invalid"));
});

test("B6: wrong profile value → profile.invalid", () => {
  assert.ok(
    verifyActionBody({ ...validBody(), profile: "other" }).errors.includes("profile.invalid"),
  );
});

test("B7: missing verb → verb.missing", () => {
  const b = validBody() as Record<string, unknown>;
  delete b.verb;
  assert.ok(verifyActionBody(b).errors.includes("verb.missing"));
});

test("B8: empty verb → verb.missing", () => {
  assert.ok(verifyActionBody({ ...validBody(), verb: "" }).errors.includes("verb.missing"));
});

test("B9: non-string verb → verb.missing", () => {
  assert.ok(verifyActionBody({ ...validBody(), verb: 5 }).errors.includes("verb.missing"));
});

test("B10: missing rule_id → rule_id.missing", () => {
  const b = validBody() as Record<string, unknown>;
  delete b.rule_id;
  assert.ok(verifyActionBody(b).errors.includes("rule_id.missing"));
});

test("B11: empty rule_id → rule_id.missing", () => {
  assert.ok(verifyActionBody({ ...validBody(), rule_id: "" }).errors.includes("rule_id.missing"));
});

test("B12: missing recipe_id → recipe_id.missing", () => {
  const b = validBody() as Record<string, unknown>;
  delete b.recipe_id;
  assert.ok(verifyActionBody(b).errors.includes("recipe_id.missing"));
});

test("B13: empty recipe_id → recipe_id.missing", () => {
  assert.ok(
    verifyActionBody({ ...validBody(), recipe_id: "" }).errors.includes("recipe_id.missing"),
  );
});

test("B14: missing outcome → outcome.invalid", () => {
  const b = validBody() as Record<string, unknown>;
  delete b.outcome;
  assert.ok(verifyActionBody(b).errors.includes("outcome.invalid"));
});

test("B15: wrong outcome value → outcome.invalid", () => {
  assert.ok(
    verifyActionBody({ ...validBody(), outcome: "pending" }).errors.includes("outcome.invalid"),
  );
});

test("B16: outcome=executed is accepted", () => {
  assert.equal(verifyActionBody({ ...validBody(), outcome: "executed" }).valid, true);
});

test("B17: outcome=failed-gave-up is accepted", () => {
  assert.equal(verifyActionBody({ ...validBody(), outcome: "failed-gave-up" }).valid, true);
});

test("B18: missing executed_at → executed_at.missing", () => {
  const b = validBody() as Record<string, unknown>;
  delete b.executed_at;
  assert.ok(verifyActionBody(b).errors.includes("executed_at.missing"));
});

test("B19: empty executed_at → executed_at.missing", () => {
  assert.ok(
    verifyActionBody({ ...validBody(), executed_at: "" }).errors.includes("executed_at.missing"),
  );
});

test("B20: missing decision_commit → decision_commit.invalid", () => {
  const b = validBody() as Record<string, unknown>;
  delete b.decision_commit;
  assert.ok(verifyActionBody(b).errors.includes("decision_commit.invalid"));
});

test("B21: decision_commit wrong prefix → decision_commit.invalid", () => {
  assert.ok(
    verifyActionBody({ ...validBody(), decision_commit: "md5:" + "a".repeat(64) }).errors.includes(
      "decision_commit.invalid",
    ),
  );
});

test("B22: decision_commit too short → decision_commit.invalid", () => {
  assert.ok(
    verifyActionBody({ ...validBody(), decision_commit: "sha256:abc" }).errors.includes(
      "decision_commit.invalid",
    ),
  );
});

test("B23: decision_commit uppercase hex → decision_commit.invalid", () => {
  assert.ok(
    verifyActionBody({ ...validBody(), decision_commit: H("A") }).errors.includes(
      "decision_commit.invalid",
    ),
  );
});

test("B24: missing params_commit → params_commit.invalid", () => {
  const b = validBody() as Record<string, unknown>;
  delete b.params_commit;
  assert.ok(verifyActionBody(b).errors.includes("params_commit.invalid"));
});

test("B25: params_commit malformed → params_commit.invalid", () => {
  assert.ok(
    verifyActionBody({ ...validBody(), params_commit: "x" }).errors.includes(
      "params_commit.invalid",
    ),
  );
});

test("B26: missing request_id_commit → request_id_commit.invalid", () => {
  const b = validBody() as Record<string, unknown>;
  delete b.request_id_commit;
  assert.ok(verifyActionBody(b).errors.includes("request_id_commit.invalid"));
});

test("B27: request_id_commit malformed → request_id_commit.invalid", () => {
  assert.ok(
    verifyActionBody({ ...validBody(), request_id_commit: 42 }).errors.includes(
      "request_id_commit.invalid",
    ),
  );
});

test("B28: multiple errors are collected", () => {
  const r = verifyActionBody({ profile: "x", verb: "", outcome: "z" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.length >= 3);
});

test("B29: invalid body returns null body", () => {
  assert.equal(verifyActionBody({ profile: "x" }).body, null);
});

test("B30: valid body is returned on success", () => {
  const r = verifyActionBody(validBody());
  assert.equal(r.body?.verb, "invoiceup.remind");
});

test("B31: extra fields do not invalidate the body", () => {
  // field_root is added issuer-side; it must not break body validation
  assert.equal(verifyActionBody({ ...validBody(), field_root: H("f") }).valid, true);
});

test("B32: undefined input → body.not_object", () => {
  assert.deepEqual(verifyActionBody(undefined).errors, ["body.not_object"]);
});

// AI Act Article 12 overlay (spec §4.7) — base verifier accepts the profile and
// shape-checks the optional field; regulatory semantics are the profile validator's job.
const ART12 = {
  system_id: "hub-operator-agent",
  system_version: "2026.06.0",
  period_start: "2026-06-20T10:00:00.000Z",
};

test("B33: profile aiact.art12 is accepted (no profile.invalid)", () => {
  const r = verifyActionBody({ ...validBody(), profile: "aiact.art12" });
  assert.ok(!r.errors.includes("profile.invalid"));
});

test("B34: well-formed aiact_art12 field passes the shape check", () => {
  const r = verifyActionBody({
    ...validBody(),
    profile: "aiact.art12",
    aiact_art12: ART12,
  });
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
});

test("B35: aiact_art12 missing a required sub-field → aiact_art12.invalid", () => {
  const r = verifyActionBody({
    ...validBody(),
    profile: "aiact.art12",
    aiact_art12: { ...ART12, system_id: "" },
  });
  assert.ok(r.errors.includes("aiact_art12.invalid"));
});

test("B36: aiact_art12 not an object → aiact_art12.invalid", () => {
  const r = verifyActionBody({
    ...validBody(),
    profile: "aiact.art12",
    aiact_art12: "nope",
  });
  assert.ok(r.errors.includes("aiact_art12.invalid"));
});

test("B37: absent aiact_art12 is fine (optional, additive)", () => {
  assert.equal(verifyActionBody(validBody()).valid, true);
});
