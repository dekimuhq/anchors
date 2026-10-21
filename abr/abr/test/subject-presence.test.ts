/**
 * Subject-presence tests for @dekimuhq/abr-verifier — Phase 3 §E.
 *
 * FAMILY-CONSISTENCY.md §3 + spec §3.1/§4.5/D10-ABR-4:
 *   - `breach.subject_notified`             → subject MUST be `"sha256:<hex>"`
 *   - every other event_type (7 events)     → subject MUST be `null`
 *
 * Coverage:
 *   U1  — subject_notified + valid sha256:<hex>                   → ok.
 *   U2  — subject_notified + null                                  → subject_must_be_present.
 *   U3  — subject_notified + empty string                          → subject_must_be_present.
 *   U4  — subject_notified + raw string                            → subject_must_be_sha256.
 *   U5a — subject_notified + uppercase hex                         → subject_must_be_sha256.
 *   U5b — subject_notified + short hex                             → subject_must_be_sha256.
 *   U6  — Every incident-level event + null                        → ok (7 events).
 *   U7  — Every incident-level event + sha256:<hex>                → subject_must_be_null (7 events).
 *   U8  — Every incident-level event + raw string                  → subject_must_be_null (7 events).
 *   U9  — Unknown event_type falls through to strict-null branch.
 *   U10 — Missing / non-object body falls through to strict-null branch.
 *   A1  — apply sets `subject_missing` on subject_notified/null.
 *   A2  — apply sets `subject_invalid_form` on subject_notified/bad-string.
 *   A3  — apply sets `subject_present` on incident-level/non-null.
 *   A4  — apply is no-op when sig already failed (first failure wins).
 *   A5  — apply is no-op on a valid receipt.
 *   I1  — verifyReceipt end-to-end: subject_notified with sha256 → valid.
 *   I2  — verifyReceipt end-to-end: subject_notified with null   → subject_missing.
 *   I3  — verifyReceipt end-to-end: detected with sha256          → subject_present.
 *   I4  — verifyReceipt end-to-end: every incident-level event mint is valid.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  verifyReceipt,
  checkAbrSubjectPresence,
  applyAbrSubjectPresence,
} from "../src/index.ts";
import type { AbrEventType } from "../src/types.ts";
import { mintValidAbr, makeResolveKey } from "./_helpers/v2-receipt.ts";

const SHA = "sha256:" + "a".repeat(64);

const INCIDENT_LEVEL_EVENTS: readonly AbrEventType[] = [
  "breach.detected",
  "breach.assessed",
  "breach.dpa_notified",
  "breach.dpa_delayed",
  "breach.subject_notification_exempted",
  "breach.contained",
  "breach.closed",
];

// ── U1–U5: `breach.subject_notified` (must-be-sha256) ────────────────────────

test("abr subject-presence: subject_notified + sha256:<hex> is accepted (U1)", () => {
  const r = checkAbrSubjectPresence({
    subject: SHA,
    body: { event_type: "breach.subject_notified" },
  });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("abr subject-presence: subject_notified + null is rejected (U2)", () => {
  const r = checkAbrSubjectPresence({
    subject: null,
    body: { event_type: "breach.subject_notified" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_present");
});

test("abr subject-presence: subject_notified + empty string is rejected (U3)", () => {
  const r = checkAbrSubjectPresence({
    subject: "",
    body: { event_type: "breach.subject_notified" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_present");
});

test("abr subject-presence: subject_notified + raw string is rejected (U4)", () => {
  const r = checkAbrSubjectPresence({
    subject: "did:web:subject.example",
    body: { event_type: "breach.subject_notified" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("abr subject-presence: subject_notified + uppercase hex is rejected (U5a)", () => {
  const r = checkAbrSubjectPresence({
    subject: "sha256:" + "A".repeat(64),
    body: { event_type: "breach.subject_notified" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("abr subject-presence: subject_notified + short hex is rejected (U5b)", () => {
  const r = checkAbrSubjectPresence({
    subject: "sha256:" + "a".repeat(63),
    body: { event_type: "breach.subject_notified" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

// ── U6–U8: every incident-level event (must-be-null) ─────────────────────────

for (const event of INCIDENT_LEVEL_EVENTS) {
  test(`abr subject-presence: ${event} + null is accepted (U6)`, () => {
    const r = checkAbrSubjectPresence({
      subject: null,
      body: { event_type: event },
    });
    assert.equal(r.ok, true);
  });

  test(`abr subject-presence: ${event} + sha256:<hex> is rejected (U7)`, () => {
    const r = checkAbrSubjectPresence({
      subject: SHA,
      body: { event_type: event },
    });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "subject_must_be_null");
  });

  test(`abr subject-presence: ${event} + raw string is rejected (U8)`, () => {
    const r = checkAbrSubjectPresence({
      subject: "anything",
      body: { event_type: event },
    });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "subject_must_be_null");
  });
}

// ── U9–U10: degenerate-body fall-through to strict-null branch ───────────────

test("abr subject-presence: unknown event_type falls through to must-be-null (U9)", () => {
  const ok = checkAbrSubjectPresence({
    subject: null,
    body: { event_type: "breach.unknown" },
  });
  assert.equal(ok.ok, true);

  const bad = checkAbrSubjectPresence({
    subject: SHA,
    body: { event_type: "breach.unknown" },
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, "subject_must_be_null");
});

test("abr subject-presence: missing / non-object body falls through to must-be-null (U10)", () => {
  const okUndef = checkAbrSubjectPresence({ subject: null, body: undefined });
  assert.equal(okUndef.ok, true);

  const okNum = checkAbrSubjectPresence({ subject: null, body: 42 });
  assert.equal(okNum.ok, true);

  const okNull = checkAbrSubjectPresence({ subject: null, body: null });
  assert.equal(okNull.ok, true);

  const badUndef = checkAbrSubjectPresence({ subject: SHA, body: undefined });
  assert.equal(badUndef.ok, false);
  assert.equal(badUndef.reason, "subject_must_be_null");
});

// ── A1–A5: apply helper ──────────────────────────────────────────────────────

test("abr subject-presence: apply sets subject_missing on subject_notified/null (A1)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: true,
  };
  applyAbrSubjectPresence(target, {
    subject: null,
    body: { event_type: "breach.subject_notified" },
  });
  assert.equal(target.signature_valid, false);
  assert.equal(target.reason, "subject_missing");
});

test("abr subject-presence: apply sets subject_invalid_form on subject_notified/bad-string (A2)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: true,
  };
  applyAbrSubjectPresence(target, {
    subject: "did:web:x",
    body: { event_type: "breach.subject_notified" },
  });
  assert.equal(target.signature_valid, false);
  assert.equal(target.reason, "subject_invalid_form");
});

test("abr subject-presence: apply sets subject_present on incident-level/sha256 (A3)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: true,
  };
  applyAbrSubjectPresence(target, {
    subject: SHA,
    body: { event_type: "breach.detected" },
  });
  assert.equal(target.signature_valid, false);
  assert.equal(target.reason, "subject_present");
});

test("abr subject-presence: apply is no-op when sig already failed (A4)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: false,
    reason: "wrong_protocol",
  };
  applyAbrSubjectPresence(target, {
    subject: null,
    body: { event_type: "breach.subject_notified" },
  });
  assert.equal(target.signature_valid, false);
  // Earlier failure must win.
  assert.equal(target.reason, "wrong_protocol");
});

test("abr subject-presence: apply is no-op on valid receipt (A5)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: true,
  };
  applyAbrSubjectPresence(target, {
    subject: SHA,
    body: { event_type: "breach.subject_notified" },
  });
  assert.equal(target.signature_valid, true);
  assert.equal(target.reason, undefined);
});

// ── I1–I4: end-to-end via verifyReceipt ──────────────────────────────────────

/**
 * Mint a `breach.subject_notified` receipt, swap its `subject` to the
 * provided value, and re-sign so the canonical signature still binds the
 * mutated field. Used to drive end-to-end §E rejection paths through
 * `verifyReceipt`.
 */
async function mintSubjectNotifiedWithSubject(
  subject: unknown,
): Promise<{ envelope: Envelope; publicKey: Uint8Array }> {
  const base = await mintValidAbr("breach.subject_notified");
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

/**
 * Mint a `breach.detected` receipt with a forced non-null subject — drives
 * the `subject_present` rejection path end-to-end.
 */
async function mintDetectedWithSubject(
  subject: unknown,
): Promise<{ envelope: Envelope; publicKey: Uint8Array }> {
  const base = await mintValidAbr("breach.detected");
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

test("abr subject-presence: subject_notified + sha256 verifies end-to-end (I1)", async () => {
  const { envelope, publicKey } = await mintValidAbr("breach.subject_notified");
  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.reason, undefined);
});

test("abr subject-presence: subject_notified + null rejects end-to-end (I2)", async () => {
  const { envelope, publicKey } = await mintSubjectNotifiedWithSubject(null);
  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "subject_missing");
});

test("abr subject-presence: detected + sha256 rejects end-to-end (I3)", async () => {
  const { envelope, publicKey } = await mintDetectedWithSubject(SHA);
  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "subject_present");
});

for (const event of INCIDENT_LEVEL_EVENTS) {
  test(`abr subject-presence: ${event} mint verifies end-to-end (I4)`, async () => {
    const { envelope, publicKey } = await mintValidAbr(event);
    const result = await verifyReceipt(envelope, {
      resolveKey: makeResolveKey(publicKey),
    });
    // `breach.detected` is MANDATORY-TSA per §D; tsa_absent poisons sig with
    // `tsa_required`. Skip that branch — §E acceptance is asserted via the
    // unit tests above for `breach.detected`.
    if (event === "breach.detected") {
      assert.equal(result.signature_valid, false);
      assert.equal(result.reason, "tsa_required");
      return;
    }
    assert.equal(result.signature_valid, true);
    assert.equal(result.reason, undefined);
  });
}
