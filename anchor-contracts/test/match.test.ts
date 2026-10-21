// test/match.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { matchPrecondition, ACCEPTABLE_STATUS_STATES } from "../src/match.ts";
import type { Precondition } from "../src/types.ts";
import { makeEnvelope, verified } from "./_fixtures.ts";

const transfer = () => makeEnvelope({ claim_type: "ar.transfer.v1", iss: "did:web:buyer.example", subject: "deal-42" });

test("matches on claim_type + issuer + subject", () => {
  const pre: Precondition = { claimType: "ar.transfer.v1", issuers: ["did:web:buyer.example"], subjectEquals: "deal-42" };
  assert.deepEqual(matchPrecondition(pre, verified(transfer())), { ok: true });
});

test("refuses an unsigned anchor (trust boundary)", () => {
  const pre: Precondition = { claimType: "ar.transfer.v1" };
  const r = matchPrecondition(pre, verified(transfer(), { signature_valid: false }));
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason, "anchor_signature_invalid");
});

test("refuses a revoked anchor by default", () => {
  const pre: Precondition = { claimType: "ar.transfer.v1" };
  const r = matchPrecondition(pre, verified(transfer(), { status_state: "revoked" }));
  assert.equal(r.ok === false && r.reason, "anchor_revoked");
});

test("notRevoked:false allows a revoked anchor", () => {
  const pre: Precondition = { claimType: "ar.transfer.v1", notRevoked: false };
  assert.deepEqual(matchPrecondition(pre, verified(transfer(), { status_state: "revoked" })), { ok: true });
});

// Trust-gate deny-by-default: every non-good-standing status_state must refuse,
// not just the exact string "revoked". These are real envelope verifier states
// (StatusCheck/SuspensionCheck["state"]) that an exact-"revoked" check would leak.
for (const bad of [
  "revoked_stale",
  "revoked_by_chain",
  "suspended",
  "suspended_stale",
  "unreachable",
  "invalid_pointer",
  "list_signature_invalid",
  "list_mismatch",
  "some_future_state_we_dont_know",
]) {
  test(`refuses a non-good-standing status_state: ${bad}`, () => {
    const pre: Precondition = { claimType: "ar.transfer.v1" };
    const r = matchPrecondition(pre, verified(transfer(), { status_state: bad }));
    assert.equal(r.ok === false && r.reason, "anchor_revoked");
  });
}

// Good-standing states (and absent status) must still fire.
for (const good of ["active", "active_stale", "no_status_pointer", "no_suspension_pointer", "not_attempted", "not_suspended", "not_suspended_stale"]) {
  test(`allows good-standing status_state: ${good}`, () => {
    const pre: Precondition = { claimType: "ar.transfer.v1" };
    assert.deepEqual(matchPrecondition(pre, verified(transfer(), { status_state: good })), { ok: true });
  });
}

test("ACCEPTABLE_STATUS_STATES excludes every revoked/suspended value", () => {
  for (const bad of ["revoked", "revoked_stale", "revoked_by_chain", "suspended", "suspended_stale"]) {
    assert.equal(ACCEPTABLE_STATUS_STATES.has(bad), false, `${bad} must not be acceptable`);
  }
});

test("wrong claim_type → precondition_unmatched", () => {
  const pre: Precondition = { claimType: "ar.consent.v1" };
  const r = matchPrecondition(pre, verified(transfer()));
  assert.equal(r.ok === false && r.reason, "precondition_unmatched");
});

test("issuer not in allowlist → unmatched", () => {
  const pre: Precondition = { claimType: "ar.transfer.v1", issuers: ["did:web:other.example"] };
  const r = matchPrecondition(pre, verified(transfer()));
  assert.equal(r.ok === false && r.reason, "precondition_unmatched");
});

test("iat outside window → unmatched", () => {
  const pre: Precondition = { claimType: "ar.transfer.v1", within: { fromIat: "2026-06-01T00:00:00Z" } };
  const r = matchPrecondition(pre, verified(transfer())); // iat 2026-05-31
  assert.equal(r.ok === false && r.reason, "precondition_unmatched");
});

test("where predicate over body must hold", () => {
  const env = makeEnvelope({ claim_type: "ar.transfer.v1", body: { amount: 100 } });
  const passes: Precondition = { claimType: "ar.transfer.v1", where: { ">=": [{ var: "body.amount" }, 100] } };
  const fails: Precondition = { claimType: "ar.transfer.v1", where: { ">=": [{ var: "body.amount" }, 200] } };
  assert.deepEqual(matchPrecondition(passes, verified(env)), { ok: true });
  assert.equal(matchPrecondition(fails, verified(env)).ok, false);
});

test("malformed where AST → predicate_invalid_ast", () => {
  const pre: Precondition = { claimType: "ar.transfer.v1", where: { bogus_op: [1, 2] } as never };
  const r = matchPrecondition(pre, verified(transfer()));
  assert.equal(r.ok === false && r.reason, "predicate_invalid_ast");
});

// --- matchAll (Task 4) ---
import { matchAll } from "../src/match.ts";

test("matchAll assigns one anchor per precondition, keyed by `as`", () => {
  const pay = makeEnvelope({ claim_type: "ar.transfer.v1", subject: "deal-42", body: { amount: 100 } });
  const ok = makeEnvelope({ claim_type: "ar.attestation.v1", subject: "deal-42" });
  const pool = [verified(pay), verified(ok)];
  const pre = [
    { as: "payment", claimType: "ar.transfer.v1" as const },
    { as: "approval", claimType: "ar.attestation.v1" as const },
  ];
  const r = matchAll(pre, pool);
  assert.equal(r.ok, true);
  assert.ok(r.ok && r.matched.payment!.claim_type === "ar.transfer.v1");
  assert.ok(r.ok && r.matched.approval!.claim_type === "ar.attestation.v1");
});

test("matchAll keys by index when `as` is absent", () => {
  const pay = makeEnvelope({ claim_type: "ar.transfer.v1" });
  const r = matchAll([{ claimType: "ar.transfer.v1" }], [verified(pay)]);
  assert.ok(r.ok && r.matched["0"]!.claim_type === "ar.transfer.v1");
});

test("matchAll fails with the first precondition's reason when unsatisfiable", () => {
  const r = matchAll([{ claimType: "ar.consent.v1" }], [verified(makeEnvelope({ claim_type: "ar.transfer.v1" }))]);
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason, "precondition_unmatched");
});

test("matchAll does not reuse one anchor for two preconditions", () => {
  const only = verified(makeEnvelope({ claim_type: "ar.transfer.v1" }));
  const r = matchAll([{ claimType: "ar.transfer.v1" }, { claimType: "ar.transfer.v1" }], [only]);
  assert.equal(r.ok, false); // second precondition starves
});
