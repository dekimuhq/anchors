/**
 * Tests for the `asrFamily` manifest (Phase 3 Task 3.1 Step 4).
 *
 * Exercises the surface most likely to drift in the lifetime of a greenfield
 * family: identity invariants, the universal sha256-format subject-presence
 * callback, profile registration with placeholder validators, and the
 * meta-block contract (chip 12, status_list_slot 6, continuity false,
 * tsa_mandate omitted).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { asrFamily } from "../src/family.ts";

test("asrFamily declares chip 12, status_list_slot 6, ar.subject_rights.v1, continuity, free TSA path", () => {
  assert.equal(asrFamily.meta.acronym, "ASR");
  assert.equal(asrFamily.meta.name, "Anchored Subject-Rights Receipts");
  assert.equal(asrFamily.meta.chip, 12);
  assert.equal(asrFamily.meta.status_list_slot, 6);
  assert.equal(asrFamily.meta.subject_presence, "must-be-present");
  assert.equal(asrFamily.meta.tsa_upgrade_path, "free");
  assert.equal(asrFamily.meta.continuity, true);
  assert.equal(asrFamily.meta.batch, false);
  assert.equal(asrFamily.meta.predicate_recommended, false);
  assert.deepEqual([...asrFamily.meta.claim_types], ["ar.subject_rights.v1"]);
});

test("asrFamily.isOwnedClaimType only accepts ar.subject_rights.v1", () => {
  assert.equal(asrFamily.isOwnedClaimType("ar.subject_rights.v1"), true);
  assert.equal(asrFamily.isOwnedClaimType("ar.notice.v1"), false);
  assert.equal(asrFamily.isOwnedClaimType("ar.consent.v1"), false);
  assert.equal(asrFamily.isOwnedClaimType("ar.lineage.v1"), false);
  assert.equal(asrFamily.isOwnedClaimType("ar.subject_rights.v2"), false);
});

test("asrFamily.checkSubjectPresence — well-formed sha256:<hex> accepted across all event types", () => {
  const sha = "sha256:" + "a".repeat(64);
  for (const event_type of [
    "request.received",
    "request.identity_verified",
    "request.scope_clarified",
    "request.extended",
    "request.partially_honoured",
    "request.fulfilled",
    "request.refused",
    "request.escalated",
    "request.recipient_notified",
  ]) {
    const body = { event_type };
    assert.deepEqual(
      asrFamily.checkSubjectPresence(sha, body),
      { ok: true },
      `well-formed subject MUST be accepted for ${event_type}`,
    );
  }
});

test("asrFamily.checkSubjectPresence — null/undefined/empty reject as subject_missing", () => {
  const body = { event_type: "request.received" };
  assert.deepEqual(
    asrFamily.checkSubjectPresence(null, body),
    { ok: false, reason: "subject_missing" },
  );
  assert.deepEqual(
    asrFamily.checkSubjectPresence(undefined, body),
    { ok: false, reason: "subject_missing" },
  );
  assert.deepEqual(
    asrFamily.checkSubjectPresence("", body),
    { ok: false, reason: "subject_missing" },
  );
});

test("asrFamily.checkSubjectPresence — malformed subject rejects as subject_invalid_form", () => {
  const body = { event_type: "request.received" };
  assert.deepEqual(
    asrFamily.checkSubjectPresence("nothex", body),
    { ok: false, reason: "subject_invalid_form" },
  );
  assert.deepEqual(
    asrFamily.checkSubjectPresence("sha256:short", body),
    { ok: false, reason: "subject_invalid_form" },
  );
  assert.deepEqual(
    asrFamily.checkSubjectPresence("md5:" + "a".repeat(32), body),
    { ok: false, reason: "subject_invalid_form" },
  );
  assert.deepEqual(
    asrFamily.checkSubjectPresence("sha256:" + "Z".repeat(64), body),
    { ok: false, reason: "subject_invalid_form" },
  );
});

test("asrFamily registers all 6 v1 profiles in spec order", () => {
  assert.deepEqual([...asrFamily.profileIds], [
    "subject_rights.art15.access",
    "subject_rights.art16.rectification",
    "subject_rights.art17.erasure_request",
    "subject_rights.art18.restriction",
    "subject_rights.art20.portability",
    "subject_rights.art21.objection",
  ]);
  for (const id of asrFamily.profileIds) {
    assert.equal(asrFamily.hasProfile(id), true);
  }
  assert.equal(asrFamily.hasProfile("subject_rights.unknown"), false);
  assert.equal(asrFamily.profileValidators.length, 6);
  for (const v of asrFamily.profileValidators) {
    assert.equal(typeof v, "function");
  }
});

test("asrFamily.tsaMandateLevel returns optional for every registered profile (tsa_mandate omitted)", () => {
  for (const id of asrFamily.profileIds) {
    assert.equal(
      asrFamily.tsaMandateLevel(id),
      "optional",
      `${id} MUST default to optional (event-keyed mandate not yet wired)`,
    );
  }
  assert.equal(asrFamily.tsaMandateLevel("subject_rights.unknown"), "optional");
  assert.equal(asrFamily.tsaMandateLevel(""), "optional");
});

test("asrFamily.validateBody passes a well-formed request.received body", () => {
  const r = asrFamily.validateBody({
    event_type: "request.received",
    subject_rights_request_id: "req-1",
    channel: "email",
    received_at: "2026-05-19T08:00:00Z",
    deadline_at: "2026-06-18T08:00:00Z",
  });
  assert.equal(r.ok, true);
});

test("asrFamily.validateBody rejects an unknown event_type", () => {
  const r = asrFamily.validateBody({
    event_type: "request.unknown",
    subject_rights_request_id: "req-1",
  });
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.reason, "asr_unknown_event_type");
  }
});

test("asrFamily.validateBody rejects a non-object body", () => {
  for (const v of [null, undefined, "string", 42, [], true]) {
    const r = asrFamily.validateBody(v);
    assert.equal(r.ok, false, `must reject ${JSON.stringify(v)}`);
    if (!r.ok) {
      assert.equal(r.reason, "asr_body_not_object");
    }
  }
});

test("asrFamily.walkParents returns [] (composition deferred to Phase 3 §G)", () => {
  assert.deepEqual(
    [...asrFamily.walkParents({ event_type: "request.received" })],
    [],
  );
});

test("asrFamily exposes generateKeypair + signCanonical (Ed25519 pre-binding)", () => {
  assert.equal(typeof asrFamily.generateKeypair, "function");
  assert.equal(typeof asrFamily.signCanonical, "function");
});

test("asrFamily exposes continuity helpers (continuity: true)", () => {
  assert.equal(typeof asrFamily.mintContinuity, "function");
  assert.equal(typeof asrFamily.verifyContinuity, "function");
});

test("asrFamily.compose is wired to composeAsr (Phase 3 §G)", () => {
  assert.equal(typeof asrFamily.compose, "function");
});

test("asrFamily.mintV2 + verifyReceipt are bound functions", () => {
  assert.equal(typeof asrFamily.mintV2, "function");
  assert.equal(typeof asrFamily.verifyReceipt, "function");
});
