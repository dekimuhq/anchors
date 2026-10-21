/**
 * Tests for the per-event-type ALR body verifier (spec §4 + §4.5).
 *
 * Coverage strategy: one happy-path per event_type plus the rejection cases
 * named explicitly in §4.1–§4.5. Cross-cutting rules (parent duplicates,
 * canonical sort, child-vs-parent hash) get dedicated cases.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAlrBody } from "../src/index.ts";

const H = (b: string) => `sha256:${b.repeat(64)}`;
const A = H("a");
const B = H("b");
const C = H("c");

function pref(artifact_hash: string, parent_apr_id: string | null = null) {
  return { artifact_hash, parent_apr_id, parent_alr_id: null, uri: null };
}

const BASE = {
  profile: "aiact.art13.transparency",
  artifact_hash: C,
  event_at: "2026-05-16T14:23:00Z",
  qts_attestation_hash: null,
};

// ── derived_from ──────────────────────────────────────────────────────────────

test("derived_from: minimal valid body -> valid", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "derived_from",
    parents: [pref(A), pref(B)], // A < B lexicographically
    successor: null,
    transform_claim: { summary: "fine-tune", uri: null },
    disclosure: null,
  });
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.errors.length, 0);
  assert.equal(out.body?.event_type, "derived_from");
});

test("derived_from: empty parents -> parents.empty", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "derived_from",
    parents: [],
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("parents.empty"));
});

test("derived_from: missing transform_claim -> transform_claim.required", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "derived_from",
    parents: [pref(A)],
    successor: null,
    transform_claim: null,
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("transform_claim.required"));
});

test("derived_from: empty summary -> transform_claim.summary.empty", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "derived_from",
    parents: [pref(A)],
    successor: null,
    transform_claim: { summary: "", uri: null },
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("transform_claim.summary.empty"));
});

test("derived_from: parents not canonical-sorted -> parents.not_canonical_sorted", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "derived_from",
    parents: [pref(B), pref(A)], // B before A — wrong order
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("parents.not_canonical_sorted"));
});

test("derived_from: duplicate parent artifact_hash -> parents.duplicate_artifact_hash", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "derived_from",
    parents: [pref(A), pref(A)],
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("parents.duplicate_artifact_hash"));
});

test("derived_from: child hash equal to a parent's -> derived_from.self_reference", () => {
  const out = verifyAlrBody({
    ...BASE,
    artifact_hash: A,
    event_type: "derived_from",
    parents: [pref(A)],
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("derived_from.self_reference"));
});

test("derived_from: non-null successor -> successor.must_be_null", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "derived_from",
    parents: [pref(A)],
    successor: pref(B),
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("successor.must_be_null"));
});

// ── forked_from ───────────────────────────────────────────────────────────────

test("forked_from: exactly one parent -> valid", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "forked_from",
    parents: [pref(A)],
    successor: null,
    transform_claim: null,
    disclosure: null,
  });
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("forked_from: zero parents -> parents.must_be_one", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "forked_from",
    parents: [],
    successor: null,
    transform_claim: null,
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("parents.must_be_one"));
});

test("forked_from: two parents -> parents.must_be_one", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "forked_from",
    parents: [pref(A), pref(B)],
    successor: null,
    transform_claim: null,
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("parents.must_be_one"));
});

// ── superseded_by ─────────────────────────────────────────────────────────────

test("superseded_by: valid forward link -> valid", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "superseded_by",
    parents: [],
    successor: pref(B),
    transform_claim: { summary: "v2.0", uri: null },
    disclosure: null,
  });
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("superseded_by: non-empty parents -> parents.must_be_empty", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "superseded_by",
    parents: [pref(A)],
    successor: pref(B),
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("parents.must_be_empty"));
});

test("superseded_by: null successor -> successor.invalid", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "superseded_by",
    parents: [],
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("successor.invalid"));
});

// ── disclosed ─────────────────────────────────────────────────────────────────

test("disclosed: valid recipient block -> valid", () => {
  const out = verifyAlrBody({
    ...BASE,
    profile: "disclosure.recipients",
    event_type: "disclosed",
    parents: [],
    successor: null,
    transform_claim: null,
    disclosure: {
      recipient: "did:web:partner.example",
      recipient_role: "processor",
      scope_hash: "sha256:" + "f".repeat(64),
      basis: "gdpr.art6.1.b",
    },
  });
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("disclosed: missing disclosure.basis -> disclosure.invalid", () => {
  const out = verifyAlrBody({
    ...BASE,
    profile: "disclosure.recipients",
    event_type: "disclosed",
    parents: [],
    successor: null,
    transform_claim: null,
    disclosure: {
      recipient: "x",
      recipient_role: "y",
      scope_hash: "z",
      // basis missing
    },
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("disclosure.invalid"));
});

test("disclosed: non-null transform_claim -> transform_claim.must_be_null", () => {
  const out = verifyAlrBody({
    ...BASE,
    profile: "disclosure.recipients",
    event_type: "disclosed",
    parents: [],
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: {
      recipient: "x",
      recipient_role: "y",
      scope_hash: "z",
      basis: "gdpr.art6.1.b",
    },
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("transform_claim.must_be_null"));
});

// ── base-shape rejections ─────────────────────────────────────────────────────

test("non-object body -> body.not_object", () => {
  assert.equal(verifyAlrBody(null).errors[0], "body.not_object");
  assert.equal(verifyAlrBody(42).errors[0], "body.not_object");
});

test("unregistered profile -> profile.unregistered", () => {
  const out = verifyAlrBody({
    ...BASE,
    profile: "made.up.profile",
    event_type: "forked_from",
    parents: [pref(A)],
    successor: null,
    transform_claim: null,
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("profile.unregistered"));
});

test("malformed artifact_hash -> artifact_hash.invalid", () => {
  const out = verifyAlrBody({
    ...BASE,
    artifact_hash: "deadbeef",
    event_type: "forked_from",
    parents: [pref(A)],
    successor: null,
    transform_claim: null,
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("artifact_hash.invalid"));
});

test("unparseable event_at -> event_at.invalid", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_at: "yesterday",
    event_type: "forked_from",
    parents: [pref(A)],
    successor: null,
    transform_claim: null,
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_at.invalid"));
});

test("unknown event_type -> event_type.unknown", () => {
  const out = verifyAlrBody({
    ...BASE,
    event_type: "deprecated_by",
    parents: [],
    successor: null,
    transform_claim: null,
    disclosure: null,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_type.unknown"));
});
