/**
 * Subject-presence tests for @dekimuhq/air-verifier — Phase 5 §E.
 *
 * FAMILY-CONSISTENCY.md §3 + spec §4.4 + D10-AIR-6:
 *   - `dpia.stakeholders_consulted` + `consultation_method ∈
 *     {representative_org, ngo_review}`  → subject MAY be null OR `"sha256:<hex>"`
 *   - `dpia.stakeholders_consulted` + any other method
 *                                         → subject MUST be null
 *   - every other event_type (10 events) → subject MUST be null
 *
 * Coverage:
 *   U1  — stakeholders_consulted + representative_org + sha256:<hex>     → ok.
 *   U2  — stakeholders_consulted + ngo_review + sha256:<hex>             → ok.
 *   U3  — stakeholders_consulted + representative_org + null             → ok.
 *   U4  — stakeholders_consulted + ngo_review + null                     → ok.
 *   U5  — stakeholders_consulted + survey + null                         → ok.
 *   U6  — stakeholders_consulted + survey + sha256:<hex>                 → method_disallows_subject.
 *   U7  — stakeholders_consulted + focus_group + sha256:<hex>            → method_disallows_subject.
 *   U8  — stakeholders_consulted + public_consultation + sha256:<hex>    → method_disallows_subject.
 *   U9  — stakeholders_consulted + internal_advisory_panel + sha256:<hex>→ method_disallows_subject.
 *   U10 — stakeholders_consulted + other + sha256:<hex>                  → method_disallows_subject.
 *   U11 — stakeholders_consulted + representative_org + empty string     → subject_must_be_sha256.
 *   U12 — stakeholders_consulted + ngo_review + raw string               → subject_must_be_sha256.
 *   U13 — stakeholders_consulted + survey + raw string                   → subject_must_be_sha256 (form check ahead of method).
 *   U14 — stakeholders_consulted + uppercase-hex sha256                  → subject_must_be_sha256.
 *   U15 — stakeholders_consulted + short hex                             → subject_must_be_sha256.
 *   U16 — stakeholders_consulted + missing consultation_method + sha256  → method_disallows_subject.
 *   U17 — Every non-stakeholders_consulted event + null                  → ok (10 events).
 *   U18 — Every non-stakeholders_consulted event + sha256:<hex>          → subject_must_be_null (10 events).
 *   U19 — Every non-stakeholders_consulted event + raw string            → subject_must_be_null (10 events).
 *   U20 — Unknown event_type falls through to strict-null branch.
 *   U21 — Missing / non-object body falls through to strict-null branch.
 *   A1  — apply sets `subject_present` on non-stakeholders_consulted/non-null.
 *   A2  — apply sets `subject_invalid_form` on stakeholders_consulted/bad-string.
 *   A3  — apply sets `representative_subject_method_mismatch` on stakeholders_consulted/sha256/other-method.
 *   A4  — apply is no-op when sig already failed (first failure wins).
 *   A5  — apply is no-op on a valid receipt.
 *   I1  — verifyReceipt end-to-end: stakeholders_consulted + survey + null is valid.
 *   I2  — verifyReceipt end-to-end: every non-stakeholders_consulted event with null subject is valid.
 *   I3  — verifyReceipt end-to-end: completed + sha256 subject              → subject_present.
 *   I4  — verifyReceipt end-to-end: stakeholders_consulted + survey + sha256 → representative_subject_method_mismatch.
 *   I5  — verifyReceipt end-to-end: stakeholders_consulted + representative_org + sha256 → valid.
 *   I6  — verifyReceipt end-to-end: stakeholders_consulted + raw-string subject → subject_invalid_form.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  verifyReceipt,
  checkAirSubjectPresence,
  applyAirSubjectPresence,
} from "../src/index.ts";
import type { AirEventType } from "../src/types.ts";
import { mintValidAir, makeResolveKey } from "./_helpers/v2-receipt.ts";
import { stakeholdersConsulted } from "./_helpers/bodies.ts";

const SHA = "sha256:" + "a".repeat(64);
const HASH = (b: string) => `sha256:${b.repeat(64)}`;

const NON_STAKEHOLDERS_EVENTS: readonly AirEventType[] = [
  "dpia.threshold_triggered",
  "dpia.scope_locked",
  "dpia.dpo_advised",
  "dpia.completed",
  "dpia.reviewed",
  "dpia.prior_consultation_initiated",
  "dpia.prior_consultation_resolved",
  "dpia.processing_authorised",
  "dpia.processing_blocked",
  "dpia.terminated",
];

// ── U1–U5: stakeholders_consulted accepted shapes ─────────────────────────────

test("air subject-presence: stakeholders_consulted + representative_org + sha256:<hex> is accepted (U1)", () => {
  const r = checkAirSubjectPresence({
    subject: SHA,
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "representative_org" },
  });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

test("air subject-presence: stakeholders_consulted + ngo_review + sha256:<hex> is accepted (U2)", () => {
  const r = checkAirSubjectPresence({
    subject: SHA,
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "ngo_review" },
  });
  assert.equal(r.ok, true);
});

test("air subject-presence: stakeholders_consulted + representative_org + null is accepted (U3)", () => {
  const r = checkAirSubjectPresence({
    subject: null,
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "representative_org" },
  });
  assert.equal(r.ok, true);
});

test("air subject-presence: stakeholders_consulted + ngo_review + null is accepted (U4)", () => {
  const r = checkAirSubjectPresence({
    subject: null,
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "ngo_review" },
  });
  assert.equal(r.ok, true);
});

test("air subject-presence: stakeholders_consulted + survey + null is accepted (U5)", () => {
  const r = checkAirSubjectPresence({
    subject: null,
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "survey" },
  });
  assert.equal(r.ok, true);
});

// ── U6–U10: stakeholders_consulted + non-bearing method + sha256 → method_disallows_subject ─

for (const method of [
  "survey",
  "focus_group",
  "public_consultation",
  "internal_advisory_panel",
  "other",
] as const) {
  test(`air subject-presence: stakeholders_consulted + ${method} + sha256:<hex> rejects with method_disallows_subject`, () => {
    const r = checkAirSubjectPresence({
      subject: SHA,
      body: { event_type: "dpia.stakeholders_consulted", consultation_method: method },
    });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "method_disallows_subject");
  });
}

// ── U11–U15: stakeholders_consulted + bad subject form → subject_must_be_sha256 ──

test("air subject-presence: stakeholders_consulted + representative_org + empty string rejects with subject_must_be_sha256 (U11)", () => {
  const r = checkAirSubjectPresence({
    subject: "",
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "representative_org" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("air subject-presence: stakeholders_consulted + ngo_review + raw string rejects with subject_must_be_sha256 (U12)", () => {
  const r = checkAirSubjectPresence({
    subject: "not-a-hash",
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "ngo_review" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("air subject-presence: stakeholders_consulted + survey + raw string rejects with subject_must_be_sha256 — form check ahead of method (U13)", () => {
  const r = checkAirSubjectPresence({
    subject: "not-a-hash",
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "survey" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("air subject-presence: stakeholders_consulted + uppercase-hex sha256 rejects with subject_must_be_sha256 (U14)", () => {
  const r = checkAirSubjectPresence({
    subject: "sha256:" + "A".repeat(64),
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "representative_org" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

test("air subject-presence: stakeholders_consulted + short hex rejects with subject_must_be_sha256 (U15)", () => {
  const r = checkAirSubjectPresence({
    subject: "sha256:" + "a".repeat(63),
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "representative_org" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_sha256");
});

// ── U16: missing consultation_method on stakeholders_consulted ────────────────

test("air subject-presence: stakeholders_consulted + missing consultation_method + sha256 rejects with method_disallows_subject (U16)", () => {
  const r = checkAirSubjectPresence({
    subject: SHA,
    body: { event_type: "dpia.stakeholders_consulted" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "method_disallows_subject");
});

// ── U17–U19: non-stakeholders_consulted events ───────────────────────────────

for (const event of NON_STAKEHOLDERS_EVENTS) {
  test(`air subject-presence: ${event} + null is accepted (U17)`, () => {
    const r = checkAirSubjectPresence({
      subject: null,
      body: { event_type: event },
    });
    assert.equal(r.ok, true);
  });
  test(`air subject-presence: ${event} + sha256:<hex> rejects with subject_must_be_null (U18)`, () => {
    const r = checkAirSubjectPresence({
      subject: SHA,
      body: { event_type: event },
    });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "subject_must_be_null");
  });
  test(`air subject-presence: ${event} + raw string rejects with subject_must_be_null (U19)`, () => {
    const r = checkAirSubjectPresence({
      subject: "not-a-hash",
      body: { event_type: event },
    });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "subject_must_be_null");
  });
}

// ── U20: unknown event_type ──────────────────────────────────────────────────

test("air subject-presence: unknown event_type + null is accepted (U20a)", () => {
  const r = checkAirSubjectPresence({
    subject: null,
    body: { event_type: "dpia.unknown_event" },
  });
  assert.equal(r.ok, true);
});

test("air subject-presence: unknown event_type + sha256 rejects with subject_must_be_null (U20b)", () => {
  const r = checkAirSubjectPresence({
    subject: SHA,
    body: { event_type: "dpia.unknown_event" },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

// ── U21: missing / malformed body ────────────────────────────────────────────

test("air subject-presence: missing body + null is accepted (U21a)", () => {
  const r = checkAirSubjectPresence({ subject: null, body: undefined });
  assert.equal(r.ok, true);
});

test("air subject-presence: null body + null is accepted (U21b)", () => {
  const r = checkAirSubjectPresence({ subject: null, body: null });
  assert.equal(r.ok, true);
});

test("air subject-presence: missing body + sha256 rejects with subject_must_be_null (U21c)", () => {
  const r = checkAirSubjectPresence({ subject: SHA, body: undefined });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "subject_must_be_null");
});

// ── A1–A5: applyAirSubjectPresence semantics ─────────────────────────────────

test("apply sets reason 'subject_present' on non-stakeholders_consulted + non-null (A1)", () => {
  const target = { signature_valid: true } as { signature_valid: boolean; reason?: string };
  applyAirSubjectPresence(target, {
    subject: SHA,
    body: { event_type: "dpia.completed" },
  });
  assert.equal(target.signature_valid, false);
  assert.equal(target.reason, "subject_present");
});

test("apply sets reason 'subject_invalid_form' on stakeholders_consulted + bad string (A2)", () => {
  const target = { signature_valid: true } as { signature_valid: boolean; reason?: string };
  applyAirSubjectPresence(target, {
    subject: "garbage",
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "representative_org" },
  });
  assert.equal(target.signature_valid, false);
  assert.equal(target.reason, "subject_invalid_form");
});

test("apply sets reason 'representative_subject_method_mismatch' on stakeholders_consulted + sha256 + survey (A3)", () => {
  const target = { signature_valid: true } as { signature_valid: boolean; reason?: string };
  applyAirSubjectPresence(target, {
    subject: SHA,
    body: { event_type: "dpia.stakeholders_consulted", consultation_method: "survey" },
  });
  assert.equal(target.signature_valid, false);
  assert.equal(target.reason, "representative_subject_method_mismatch");
});

test("apply is no-op when signature_valid already false (A4)", () => {
  const target = { signature_valid: false, reason: "prior_failure" } as {
    signature_valid: boolean;
    reason?: string;
  };
  applyAirSubjectPresence(target, {
    subject: SHA,
    body: { event_type: "dpia.completed" },
  });
  assert.equal(target.signature_valid, false);
  assert.equal(target.reason, "prior_failure");
});

test("apply is no-op on a valid receipt (A5)", () => {
  const target = { signature_valid: true } as { signature_valid: boolean; reason?: string };
  applyAirSubjectPresence(target, {
    subject: null,
    body: { event_type: "dpia.completed" },
  });
  assert.equal(target.signature_valid, true);
  assert.equal(target.reason, undefined);
});

// ── I1–I6: end-to-end verifyReceipt integration ──────────────────────────────

async function reSignWith(
  envelope: Envelope,
  privKey: crypto.KeyObject,
  patch: Partial<Envelope>,
): Promise<Envelope> {
  const merged = { ...envelope, ...patch, sig: "" } as Envelope;
  return signEnvelope(merged, privKey);
}

async function mintAirWithPatch(
  event_type: AirEventType,
  patch: { subject?: unknown; body?: Record<string, unknown> },
): Promise<{ envelope: Envelope; publicKey: Uint8Array }> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const base = await mintValidAir(event_type);
  const unsigned = {
    ...base.envelope,
    iss_key,
    body: patch.body
      ? { ...(base.envelope.body as Record<string, unknown>), ...patch.body }
      : base.envelope.body,
    subject: (patch.subject !== undefined ? patch.subject : base.envelope.subject) as Envelope["subject"],
    sig: "",
  } as Envelope;
  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

test("I1 — verifyReceipt: stakeholders_consulted + survey + null subject is valid", async () => {
  const { envelope, publicKey } = await mintAirWithPatch("dpia.stakeholders_consulted", {
    subject: null,
    body: { consultation_method: "survey" },
  });
  const r = await verifyReceipt(envelope, { resolveKey: makeResolveKey(publicKey) });
  assert.equal(r.signature_valid, true);
  assert.equal(r.reason, undefined);
});

test("I2 — verifyReceipt: every non-stakeholders_consulted event with null subject is valid", async () => {
  for (const event of NON_STAKEHOLDERS_EVENTS) {
    const { envelope, publicKey } = await mintValidAir(event);
    const r = await verifyReceipt(envelope, { resolveKey: makeResolveKey(publicKey) });
    assert.equal(r.signature_valid, true, `${event} should verify cleanly: ${r.reason}`);
  }
});

test("I3 — verifyReceipt: completed + sha256 subject rejects with subject_present", async () => {
  const { envelope, publicKey } = await mintAirWithPatch("dpia.completed", { subject: SHA });
  const r = await verifyReceipt(envelope, { resolveKey: makeResolveKey(publicKey) });
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "subject_present");
});

test("I4 — verifyReceipt: stakeholders_consulted + survey + sha256 rejects with representative_subject_method_mismatch", async () => {
  const { envelope, publicKey } = await mintAirWithPatch("dpia.stakeholders_consulted", {
    subject: SHA,
    body: { consultation_method: "survey" },
  });
  const r = await verifyReceipt(envelope, { resolveKey: makeResolveKey(publicKey) });
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "representative_subject_method_mismatch");
});

test("I5 — verifyReceipt: stakeholders_consulted + representative_org + sha256 is valid", async () => {
  const { envelope, publicKey } = await mintAirWithPatch("dpia.stakeholders_consulted", {
    subject: SHA,
    body: { consultation_method: "representative_org" },
  });
  const r = await verifyReceipt(envelope, { resolveKey: makeResolveKey(publicKey) });
  assert.equal(r.signature_valid, true, `expected valid, got ${r.reason}`);
});

test("I6 — verifyReceipt: stakeholders_consulted + ngo_review + raw-string subject rejects with subject_invalid_form", async () => {
  const { envelope, publicKey } = await mintAirWithPatch("dpia.stakeholders_consulted", {
    subject: "not-a-hash",
    body: { consultation_method: "ngo_review" },
  });
  const r = await verifyReceipt(envelope, { resolveKey: makeResolveKey(publicKey) });
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "subject_invalid_form");
});

// silence unused-import linter for helpers reserved for future fixtures
void HASH;
void reSignWith;
void stakeholdersConsulted;
