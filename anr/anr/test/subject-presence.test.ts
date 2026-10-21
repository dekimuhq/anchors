/**
 * Subject-presence tests for @dekimuhq/anr-verifier — Phase 2 §E.
 *
 * FAMILY-CONSISTENCY.md §3 per-event-type split:
 *   - `notice.acknowledged`  → subject MUST be `"sha256:<hex>"`
 *   - every other event_type → subject MAY be `"sha256:<hex>"` OR `null`
 *
 * Coverage:
 *   U1 — ack event + valid sha256:<hex> subject               → ok.
 *   U2 — ack event + null subject                             → subject_must_be_present.
 *   U3 — ack event + non-sha256 string                        → subject_must_be_sha256.
 *   U4 — ack event + malformed sha256 (uppercase / short hex) → subject_must_be_sha256.
 *   U5 — non-ack event + null subject                         → ok.
 *   U6 — non-ack event + valid sha256:<hex>                   → ok.
 *   U7 — non-ack event + raw string                           → subject_must_be_sha256.
 *   U8 — unknown event_type falls through to permissive rule  → ok on null.
 *   U9 — missing body / non-object body falls through         → ok on null.
 *   A1 — applyAnrSubjectPresence sets `subject_missing` on ack/null.
 *   A2 — applyAnrSubjectPresence sets `subject_invalid_form` on bad string.
 *   A3 — applyAnrSubjectPresence is a no-op when sig already failed.
 *   A4 — applyAnrSubjectPresence is a no-op on a valid receipt.
 *   I1 — verifyReceipt end-to-end: ack receipt with sha256 subject → valid.
 *   I2 — verifyReceipt end-to-end: ack receipt with null subject → subject_missing.
 *   I3 — verifyReceipt end-to-end: presented receipt with raw string → subject_invalid_form.
 *   I4 — Every non-ack event_type accepts a valid sha256 subject.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  verifyReceipt,
  checkAnrSubjectPresence,
  applyAnrSubjectPresence,
} from "../src/index.ts";
import type { AnrBody } from "../src/types.ts";
import { mintValidAnr, makeResolveKey } from "./_helpers/v2-receipt.ts";

const SHA = "sha256:" + "a".repeat(64);

function ackBody(): AnrBody {
  return {
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    event_type: "notice.acknowledged",
    jurisdiction: "EU",
    ack_method: "checkbox",
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    base_anr_id: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
  };
}

// ── U1–U4: ack event variants ────────────────────────────────────────────────

test("anr subject-presence: ack + sha256:<hex> is accepted (U1)", () => {
  const r = checkAnrSubjectPresence({
    subject: SHA,
    body: { event_type: "notice.acknowledged" },
  });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("anr subject-presence: ack + null is rejected (U2)", () => {
  const r = checkAnrSubjectPresence({
    subject: null,
    body: { event_type: "notice.acknowledged" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_present");
});

test("anr subject-presence: ack + raw string is rejected (U3)", () => {
  const r = checkAnrSubjectPresence({
    subject: "did:web:subject.example",
    body: { event_type: "notice.acknowledged" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("anr subject-presence: ack + uppercase hex is rejected (U4a)", () => {
  const r = checkAnrSubjectPresence({
    subject: "sha256:" + "A".repeat(64),
    body: { event_type: "notice.acknowledged" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("anr subject-presence: ack + short hex is rejected (U4b)", () => {
  const r = checkAnrSubjectPresence({
    subject: "sha256:" + "a".repeat(63),
    body: { event_type: "notice.acknowledged" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

// ── U5–U7: non-ack event variants ────────────────────────────────────────────

test("anr subject-presence: presented + null is accepted (U5)", () => {
  const r = checkAnrSubjectPresence({
    subject: null,
    body: { event_type: "notice.presented" },
  });
  assert.equal(r.ok, true);
});

test("anr subject-presence: presented + sha256:<hex> is accepted (U6)", () => {
  const r = checkAnrSubjectPresence({
    subject: SHA,
    body: { event_type: "notice.presented" },
  });
  assert.equal(r.ok, true);
});

test("anr subject-presence: presented + raw string is rejected (U7)", () => {
  const r = checkAnrSubjectPresence({
    subject: "anonymous",
    body: { event_type: "notice.presented" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

// ── U8–U9: degenerate-body fall-through ──────────────────────────────────────

test("anr subject-presence: unknown event_type falls through to permissive branch (U8)", () => {
  // Unknown discriminator → non-ack rule applies; null OK, raw string rejected.
  const ok = checkAnrSubjectPresence({
    subject: null,
    body: { event_type: "notice.unknown" },
  });
  assert.equal(ok.ok, true);

  const bad = checkAnrSubjectPresence({
    subject: "x",
    body: { event_type: "notice.unknown" },
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, "subject_must_be_sha256");
});

test("anr subject-presence: missing body falls through to permissive branch (U9)", () => {
  const ok = checkAnrSubjectPresence({ subject: null, body: undefined });
  assert.equal(ok.ok, true);

  const ok2 = checkAnrSubjectPresence({ subject: null, body: 42 });
  assert.equal(ok2.ok, true);
});

// ── A1–A4: apply helper ──────────────────────────────────────────────────────

test("anr subject-presence: apply sets subject_missing on ack/null (A1)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: true,
  };
  applyAnrSubjectPresence(target, {
    subject: null,
    body: { event_type: "notice.acknowledged" },
  });
  assert.equal(target.signature_valid, false);
  assert.equal(target.reason, "subject_missing");
});

test("anr subject-presence: apply sets subject_invalid_form on bad string (A2)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: true,
  };
  applyAnrSubjectPresence(target, {
    subject: "did:web:x",
    body: { event_type: "notice.presented" },
  });
  assert.equal(target.signature_valid, false);
  assert.equal(target.reason, "subject_invalid_form");
});

test("anr subject-presence: apply is no-op when sig already failed (A3)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: false,
    reason: "wrong_protocol",
  };
  applyAnrSubjectPresence(target, {
    subject: null,
    body: { event_type: "notice.acknowledged" },
  });
  assert.equal(target.signature_valid, false);
  // Earlier failure must win.
  assert.equal(target.reason, "wrong_protocol");
});

test("anr subject-presence: apply is no-op on valid receipt (A4)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: true,
  };
  applyAnrSubjectPresence(target, {
    subject: SHA,
    body: { event_type: "notice.acknowledged" },
  });
  assert.equal(target.signature_valid, true);
  assert.equal(target.reason, undefined);
});

// ── I1–I4: end-to-end via verifyReceipt ──────────────────────────────────────

async function mintAck(subject: unknown): Promise<{
  envelope: Envelope;
  publicKey: Uint8Array;
}> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ANRSUB1",
    claim_type: "ar.notice.v1",
    iss: "did:web:controller.example",
    iss_key,
    subject: subject as string,
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://controller.example/notice/v1",
    policy_hash: "sha256:" + "e".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: ackBody(),
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

async function mintPresentedWithSubject(subject: unknown): Promise<{
  envelope: Envelope;
  publicKey: Uint8Array;
}> {
  const base = await mintValidAnr("notice.art13.collected_direct");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    ...base.envelope,
    iss_key,
    subject: subject as string,
    sig: "",
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

test("anr subject-presence: ack + sha256 verifies end-to-end (I1)", async () => {
  const { envelope, publicKey } = await mintAck(SHA);
  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.reason, undefined);
});

test("anr subject-presence: ack + null rejects end-to-end (I2)", async () => {
  const { envelope, publicKey } = await mintAck(null);
  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "subject_missing");
});

test("anr subject-presence: presented + raw string rejects end-to-end (I3)", async () => {
  const { envelope, publicKey } = await mintPresentedWithSubject("anonymous");
  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "subject_invalid_form");
});

test("anr subject-presence: presented + sha256 verifies end-to-end (I4)", async () => {
  const { envelope, publicKey } = await mintPresentedWithSubject(SHA);
  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.reason, undefined);
});
