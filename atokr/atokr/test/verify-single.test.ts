/**
 * Tests for the per-event-type ATokR body verifier (spec §4 + D10-ATokR-1..7).
 *
 * Coverage: one happy path per event_type plus the rejection cases named
 * explicitly in §4.1–§4.4, plus shared field failures (body.not_object,
 * event_type.unknown, token_id.missing) and scope shape errors.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAtokrBody } from "../src/verify-single.ts";
import type { AtokrScope } from "../src/types.ts";

// ── Shared fixtures ───────────────────────────────────────────────────────────

const SCOPE: AtokrScope = {
  audience: "internal-payments",
  purpose: "process_payment",
  valid_from: "2026-01-01T00:00:00Z",
  valid_until: null,
  single_use: false,
};

function issued(over: Record<string, unknown> = {}) {
  return {
    event_type: "token.issued",
    token_id: "tok_abc123",
    format_class: "pan",
    scope: SCOPE,
    rotation_of: null,
    redemption_audit_ref: null,
    asr_ref: null,
    arr_ref: null,
    alr_ref: null,
    apur_ref: null,
    ...over,
  };
}

function redeemed(over: Record<string, unknown> = {}) {
  return {
    event_type: "token.redeemed",
    token_id: "tok_abc123",
    format_class: null,
    scope: SCOPE,
    rotation_of: null,
    redemption_audit_ref: null,
    asr_ref: null,
    arr_ref: null,
    alr_ref: null,
    apur_ref: null,
    ...over,
  };
}

function revoked(over: Record<string, unknown> = {}) {
  return {
    event_type: "token.revoked",
    token_id: "tok_abc123",
    format_class: null,
    scope: SCOPE,
    rotation_of: null,
    redemption_audit_ref: null,
    asr_ref: null,
    arr_ref: null,
    alr_ref: null,
    apur_ref: null,
    ...over,
  };
}

function rotated(over: Record<string, unknown> = {}) {
  return {
    event_type: "token.rotated",
    token_id: "tok_def456",
    format_class: "email",
    scope: SCOPE,
    rotation_of: "tok_abc123",
    redemption_audit_ref: null,
    asr_ref: null,
    arr_ref: null,
    alr_ref: null,
    apur_ref: null,
    ...over,
  };
}

// ── Happy paths (one per event type) ─────────────────────────────────────────

test("token.issued: minimal valid body -> valid", () => {
  const out = verifyAtokrBody(issued());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "token.issued");
});

test("token.redeemed: minimal valid body (null format_class) -> valid", () => {
  const out = verifyAtokrBody(redeemed());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "token.redeemed");
});

test("token.revoked: minimal valid body (null format_class) -> valid", () => {
  const out = verifyAtokrBody(revoked());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "token.revoked");
});

test("token.rotated: minimal valid body -> valid", () => {
  const out = verifyAtokrBody(rotated());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "token.rotated");
});

// ── Shared field rejections ───────────────────────────────────────────────────

test("non-object body -> body.not_object", () => {
  assert.equal(verifyAtokrBody(null).errors[0], "body.not_object");
  assert.equal(verifyAtokrBody(42).errors[0], "body.not_object");
  assert.equal(verifyAtokrBody("body").errors[0], "body.not_object");
});

test("missing event_type -> event_type.unknown", () => {
  const out = verifyAtokrBody({ ...issued(), event_type: undefined });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_type.unknown"), out.errors.join("|"));
});

test("unknown event_type -> event_type.unknown", () => {
  const out = verifyAtokrBody({ ...issued(), event_type: "token.expired" });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_type.unknown"), out.errors.join("|"));
});

// ── token.issued specific ─────────────────────────────────────────────────────

test("token.issued: missing token_id -> token_id.missing", () => {
  const out = verifyAtokrBody(issued({ token_id: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("token_id.missing"), out.errors.join("|"));
});

test("token.issued: null format_class -> format_class.required_on_issued", () => {
  const out = verifyAtokrBody(issued({ format_class: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("format_class.required_on_issued"), out.errors.join("|"));
});

test("token.issued: invalid format_class -> format_class.invalid", () => {
  const out = verifyAtokrBody(issued({ format_class: "credit_card" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("format_class.invalid"), out.errors.join("|"));
});

test("token.issued: missing scope -> scope.required", () => {
  const out = verifyAtokrBody(issued({ scope: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("scope.required"), out.errors.join("|"));
});

test("token.issued: scope missing audience -> scope.audience.invalid", () => {
  const out = verifyAtokrBody(issued({ scope: { ...SCOPE, audience: "" } }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("scope.audience.invalid"), out.errors.join("|"));
});

test("token.issued: scope missing purpose -> scope.purpose.invalid", () => {
  const out = verifyAtokrBody(issued({ scope: { ...SCOPE, purpose: "" } }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("scope.purpose.invalid"), out.errors.join("|"));
});

test("token.issued: scope missing valid_from -> scope.valid_from.invalid", () => {
  const out = verifyAtokrBody(issued({ scope: { ...SCOPE, valid_from: "" } }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("scope.valid_from.invalid"), out.errors.join("|"));
});

test("token.issued: scope non-boolean single_use -> scope.single_use.invalid", () => {
  const out = verifyAtokrBody(issued({ scope: { ...SCOPE, single_use: "yes" } }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("scope.single_use.invalid"), out.errors.join("|"));
});

test("token.issued: non-null rotation_of -> rotation_of.must_be_null", () => {
  const out = verifyAtokrBody(issued({ rotation_of: "tok_prev" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("rotation_of.must_be_null"), out.errors.join("|"));
});

// ── token.redeemed specific ───────────────────────────────────────────────────

test("token.redeemed: missing scope -> scope.required", () => {
  const out = verifyAtokrBody(redeemed({ scope: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("scope.required"), out.errors.join("|"));
});

test("token.redeemed: non-null rotation_of -> rotation_of.must_be_null", () => {
  const out = verifyAtokrBody(redeemed({ rotation_of: "tok_prev" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("rotation_of.must_be_null"), out.errors.join("|"));
});

test("token.redeemed: valid format_class present -> valid", () => {
  const out = verifyAtokrBody(redeemed({ format_class: "iban" }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

// ── token.revoked specific ────────────────────────────────────────────────────

test("token.revoked: missing scope -> scope.required", () => {
  const out = verifyAtokrBody(revoked({ scope: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("scope.required"), out.errors.join("|"));
});

// ── token.rotated specific ────────────────────────────────────────────────────

test("token.rotated: null rotation_of -> rotation_of.required", () => {
  const out = verifyAtokrBody(rotated({ rotation_of: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("rotation_of.required"), out.errors.join("|"));
});

test("token.rotated: null format_class -> format_class.required_on_rotated", () => {
  const out = verifyAtokrBody(rotated({ format_class: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("format_class.required_on_rotated"), out.errors.join("|"));
});
