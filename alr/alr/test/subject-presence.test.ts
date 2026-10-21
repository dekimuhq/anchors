/**
 * Subject-presence tests for @dekimuhq/alr-verifier — Phase 1 §E.
 *
 * FAMILY-CONSISTENCY.md §3: ALR `subject` MUST be `null` on every event_type
 * (lineage is dataset-level). Body carries the artifact discriminators.
 *
 * Coverage:
 *   U1 — `checkAlrSubjectPresence({ subject: null })`           → ok.
 *   U2 — `checkAlrSubjectPresence({ subject: "sha256:..." })`   → rejected.
 *   U3 — `checkAlrSubjectPresence({ subject: "" })`             → rejected
 *        (empty string is NOT null; the rule is strict).
 *   U4 — `applyAlrSubjectPresence` mutates target on reject and is a no-op
 *        when `target.signature_valid` is already false.
 *   I1 — End-to-end `verifyReceipt` with `subject: "sha256:..."` →
 *        `signature_valid: false`, `reason: "subject_present"`.
 *   I2 — End-to-end happy-path receipt (`subject: null`) verifies.
 *   I3 — Every ALR event_type carries the same null-subject rule.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import * as crypto from "node:crypto";
import {
  verifyReceipt,
  checkAlrSubjectPresence,
  applyAlrSubjectPresence,
} from "../src/index.ts";
import type { AlrEventType } from "../src/types.ts";
import { mintValidAlr, makeResolveKey } from "./_helpers/v2-receipt.ts";

// ── U1 — null subject passes ─────────────────────────────────────────────────

test("alr subject-presence: null subject is accepted (U1)", () => {
  const r = checkAlrSubjectPresence({ subject: null });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

// ── U2 — non-null string subject rejected ────────────────────────────────────

test("alr subject-presence: sha256-string subject is rejected (U2)", () => {
  const r = checkAlrSubjectPresence({
    subject: "sha256:" + "a".repeat(64),
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

// ── U3 — empty-string subject also rejected ──────────────────────────────────

test("alr subject-presence: empty-string subject is rejected (U3)", () => {
  const r = checkAlrSubjectPresence({ subject: "" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

// ── U4 — apply* helper mutates + is no-op when sig already failed ────────────

test("alr subject-presence: applyAlrSubjectPresence mutates on reject (U4a)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: true,
  };
  applyAlrSubjectPresence(target, { subject: "did:web:x" });
  assert.equal(target.signature_valid, false);
  assert.equal(target.reason, "subject_present");
});

test("alr subject-presence: applyAlrSubjectPresence is no-op when sig already invalid (U4b)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: false,
    reason: "wrong_protocol",
  };
  applyAlrSubjectPresence(target, { subject: "did:web:x" });
  assert.equal(target.signature_valid, false);
  // Earlier failure must win.
  assert.equal(target.reason, "wrong_protocol");
});

test("alr subject-presence: applyAlrSubjectPresence no-ops on valid null subject (U4c)", () => {
  const target: { signature_valid: boolean; reason?: string } = {
    signature_valid: true,
  };
  applyAlrSubjectPresence(target, { subject: null });
  assert.equal(target.signature_valid, true);
  assert.equal(target.reason, undefined);
});

// ── I1 — verifyReceipt rejects when subject is non-null ──────────────────────

async function mintWithSubject(subject: unknown): Promise<{
  envelope: Envelope;
  publicKey: Uint8Array;
}> {
  // Re-mint with a non-null subject. Sign over the divergent payload so the
  // rejection is exercised by the subject-presence rule, not by signature
  // verification failing first.
  const base = await mintValidAlr("derived_from");
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

test("alr subject-presence: verifyReceipt rejects sha256 subject end-to-end (I1)", async () => {
  const { envelope, publicKey } = await mintWithSubject(
    "sha256:" + "f".repeat(64),
  );
  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "subject_must_be_null");
});

// ── I2 — happy-path (subject: null) verifies ─────────────────────────────────

test("alr subject-presence: happy-path null-subject receipt verifies (I2)", async () => {
  const { envelope, publicKey } = await mintValidAlr("derived_from");
  // Sanity: the helper now sets subject to runtime null.
  assert.equal(
    (envelope as unknown as { subject: unknown }).subject,
    null,
  );
  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.reason, undefined);
});

// ── I3 — rule is uniform across all four event_types ─────────────────────────

const EVENT_TYPES: AlrEventType[] = [
  "derived_from",
  "forked_from",
  "superseded_by",
  "disclosed",
];

for (const event_type of EVENT_TYPES) {
  test(`alr subject-presence: ${event_type} accepts null subject (I3.${event_type})`, async () => {
    const { envelope, publicKey } = await mintValidAlr(event_type);
    const result = await verifyReceipt(envelope, {
      resolveKey: makeResolveKey(publicKey),
    });
    assert.equal(result.signature_valid, true);
  });
}
