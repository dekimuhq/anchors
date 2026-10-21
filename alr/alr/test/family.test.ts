/**
 * Tests for the ALR family manifest (Phase A.2 — defineFamily() canary).
 *
 * Asserts:
 *   - Manifest meta matches FAMILY-CONSISTENCY.md (chip #9, status_list_slot=1,
 *     subject must-be-null, TSA free upgrade path, single owned claim_type).
 *   - `validateBody` round-trips the per-event-type body verifier (delegates
 *     to `verifyAlrBody`).
 *   - `isOwnedClaimType` reflects the ALR claim_type allowlist.
 *   - `checkSubjectPresence` mirrors the FAMILY-CONSISTENCY §3 rule
 *     (null OK, string rejected).
 *   - `walkParents` returns canonical-sorted APR refs for lineage bodies and
 *     empty for `superseded_by` / `disclosed`.
 *
 * Public-API regression: `alrFamily` must be exported from the package
 * barrel. Importing from "../src/index.ts" guards that.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { alrFamily } from "../src/index.ts";

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

// ── meta ─────────────────────────────────────────────────────────────────────

test("alrFamily.meta matches FAMILY-CONSISTENCY (chip 9, slot 1, must-be-null, free TSA)", () => {
  assert.equal(alrFamily.meta.acronym, "ALR");
  assert.equal(alrFamily.meta.name, "Anchored Lineage Receipts");
  assert.equal(alrFamily.meta.chip, 9);
  assert.equal(alrFamily.meta.status_list_slot, 1);
  assert.equal(alrFamily.meta.subject_presence, "must-be-null");
  assert.equal(alrFamily.meta.tsa_upgrade_path, "free");
  assert.deepEqual([...alrFamily.meta.claim_types], ["ar.lineage.v1"]);
  assert.equal(alrFamily.meta.continuity, true);
  assert.equal(alrFamily.meta.batch, false);
  assert.equal(alrFamily.meta.predicate_recommended, false);
});

test("alrFamily.meta is frozen", () => {
  assert.equal(Object.isFrozen(alrFamily.meta), true);
  assert.equal(Object.isFrozen(alrFamily.meta.claim_types), true);
});

// ── isOwnedClaimType ─────────────────────────────────────────────────────────

test("isOwnedClaimType accepts ar.lineage.v1 only", () => {
  assert.equal(alrFamily.isOwnedClaimType("ar.lineage.v1"), true);
  assert.equal(alrFamily.isOwnedClaimType("ar.provenance.v1"), false);
  assert.equal(alrFamily.isOwnedClaimType("ar.consent.v1"), false);
  assert.equal(alrFamily.isOwnedClaimType("ar.notice.v1"), false);
  assert.equal(alrFamily.isOwnedClaimType(""), false);
});

// ── checkSubjectPresence ─────────────────────────────────────────────────────

test("checkSubjectPresence accepts null", () => {
  const r = alrFamily.checkSubjectPresence(null);
  assert.equal(r.ok, true);
});

test("checkSubjectPresence rejects empty string", () => {
  const r = alrFamily.checkSubjectPresence("");
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "subject_must_be_null");
});

test("checkSubjectPresence rejects sha256-style subject", () => {
  const r = alrFamily.checkSubjectPresence(`sha256:${"a".repeat(64)}`);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "subject_must_be_null");
});

test("checkSubjectPresence rejects undefined", () => {
  const r = alrFamily.checkSubjectPresence(undefined);
  assert.equal(r.ok, false);
});

// ── validateBody ─────────────────────────────────────────────────────────────

test("validateBody accepts a valid derived_from body and returns narrowed body", () => {
  const body = {
    ...BASE,
    event_type: "derived_from",
    parents: [pref(A), pref(B)],
    successor: null,
    transform_claim: { summary: "fine-tune", uri: null },
    disclosure: null,
  };
  const r = alrFamily.validateBody(body);
  assert.equal(r.ok, true, r.ok ? "" : r.reason);
  if (r.ok) assert.equal(r.value.event_type, "derived_from");
});

test("validateBody surfaces verify-single's first error code on invalid body", () => {
  const body = {
    ...BASE,
    event_type: "derived_from",
    parents: [],
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  };
  const r = alrFamily.validateBody(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "parents.empty");
});

test("validateBody rejects non-object input without throwing", () => {
  const r = alrFamily.validateBody(null);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "body.not_object");
});

// ── walkParents ──────────────────────────────────────────────────────────────

test("walkParents returns canonical-sorted APR refs for derived_from", () => {
  const body = {
    ...BASE,
    event_type: "derived_from",
    parents: [
      pref(A, "alpha:1"),
      pref(B, "bravo:1"),
    ],
    successor: null,
    transform_claim: { summary: "fine-tune", uri: null },
    disclosure: null,
  };
  const refs = alrFamily.walkParents(body);
  assert.deepEqual([...refs], ["alpha:1", "bravo:1"]);
});

test("walkParents returns [] for superseded_by body", () => {
  const body = {
    ...BASE,
    event_type: "superseded_by",
    parents: [],
    successor: pref(A, "alpha:1"),
    transform_claim: { summary: "rev", uri: null },
    disclosure: null,
  };
  const refs = alrFamily.walkParents(body);
  assert.equal(refs.length, 0);
});

test("walkParents returns [] for disclosed body", () => {
  const body = {
    ...BASE,
    event_type: "disclosed",
    parents: [],
    successor: null,
    transform_claim: null,
    disclosure: {
      recipient: "Acme Co",
      recipient_role: "processor",
      scope_hash: `sha256:${"d".repeat(64)}`,
      basis: "gdpr.art6.1.f",
    },
  };
  const refs = alrFamily.walkParents(body);
  assert.equal(refs.length, 0);
});

test("walkParents on non-object returns []", () => {
  assert.deepEqual([...alrFamily.walkParents(null)], []);
  assert.deepEqual([...alrFamily.walkParents("not an object")], []);
});

// ── profileValidators registry (5 profiles wired after A2 migration) ────────

test("alrFamily has 5 profiles registered", () => {
  assert.equal(alrFamily.profileIds.length, 5);
  assert.equal(alrFamily.hasProfile("gdpr.art13.transparency"), true);
  assert.equal(alrFamily.hasProfile("aiact.art13.transparency"), true);
  assert.equal(alrFamily.hasProfile("aiact.art53.gpai-training"), true);
  assert.equal(alrFamily.hasProfile("c2pa.non-media"), true);
  assert.equal(alrFamily.hasProfile("disclosure.recipients"), true);
});
