/**
 * Tests for the per-event-type AAR body verifier (spec §4 + D12-AAR).
 *
 * Coverage:
 *   — Happy paths: valid issuance + valid revocation.
 *   — Shared rejections: body.not_object, event_type.unknown.
 *   — Issuance: service_type.invalid, service_policy_oid.missing,
 *     service_recipient_commit.invalid, artefact_metadata_commit.invalid,
 *     artefact_hash conditionals, signature_format conditionals,
 *     qcert_serial_commit conditionals, TSL field validation,
 *     atr_transfer_hash optional.
 *   — Revocation: reason.invalid, reason_ref_hash optional, TSL fields.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAarBody } from "../src/verify-single.ts";

// ── Shared fixtures ───────────────────────────────────────────────────────────

const SHA = (n = 1) => "sha256:" + n.toString(16).padStart(64, "0");
const VALID_TSL = {
  tsl_country: "DE",
  tsl_entry_hash: SHA(1),
  tsl_signed_tree_head_root: SHA(2),
  tsl_tree_size: 42,
  tsl_inclusion_proof: [SHA(3), SHA(4)],
  tsl_log_time: "2026-01-01T00:00:00Z",
};

function issuance(over: Record<string, unknown> = {}) {
  return {
    event_type: "issuance",
    service_type: "qwallet",
    service_policy_oid: "0.4.0.19422.1.1",
    service_recipient_commit: SHA(10),
    artefact_metadata_commit: SHA(11),
    artefact_hash: null,
    signature_format: null,
    qcert_serial_commit: null,
    atr_transfer_hash: null,
    ...VALID_TSL,
    ...over,
  };
}

function qesIssuance(over: Record<string, unknown> = {}) {
  return issuance({
    service_type: "qes",
    artefact_hash: SHA(20),
    signature_format: "pades_b_lta",
    qcert_serial_commit: SHA(21),
    ...over,
  });
}

function revocation(over: Record<string, unknown> = {}) {
  return {
    event_type: "revocation",
    reason: "key_compromise",
    reason_ref_hash: null,
    ...VALID_TSL,
    ...over,
  };
}

// ── Happy paths ───────────────────────────────────────────────────────────────

test("issuance: minimal valid body (qwallet, no artefact_hash) -> valid", () => {
  const out = verifyAarBody(issuance());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "issuance");
});

test("issuance: qes with all required conditional fields -> valid", () => {
  const out = verifyAarBody(qesIssuance());
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("issuance: qts with artefact_hash -> valid", () => {
  const out = verifyAarBody(issuance({ service_type: "qts", artefact_hash: SHA(20) }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("revocation: minimal valid body -> valid", () => {
  const out = verifyAarBody(revocation());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "revocation");
});

test("revocation: with valid reason_ref_hash -> valid", () => {
  const out = verifyAarBody(revocation({ reason_ref_hash: SHA(99) }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

// ── Shared field rejections ───────────────────────────────────────────────────

test("non-object body -> body.not_object", () => {
  assert.equal(verifyAarBody(null).errors[0], "body.not_object");
  assert.equal(verifyAarBody(42).errors[0], "body.not_object");
  assert.equal(verifyAarBody("body").errors[0], "body.not_object");
});

test("unknown event_type -> event_type.unknown", () => {
  const out = verifyAarBody({ ...issuance(), event_type: "transfer" });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_type.unknown"), out.errors.join("|"));
});

test("undefined event_type -> event_type.unknown", () => {
  const out = verifyAarBody({ ...issuance(), event_type: undefined });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_type.unknown"), out.errors.join("|"));
});

// ── Issuance: service_type ────────────────────────────────────────────────────

test("issuance: invalid service_type -> service_type.invalid", () => {
  const out = verifyAarBody(issuance({ service_type: "qtsp" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("service_type.invalid"), out.errors.join("|"));
});

test("issuance: null service_type -> service_type.invalid", () => {
  const out = verifyAarBody(issuance({ service_type: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("service_type.invalid"), out.errors.join("|"));
});

// ── Issuance: required commit fields ─────────────────────────────────────────

test("issuance: missing service_policy_oid -> service_policy_oid.missing", () => {
  const out = verifyAarBody(issuance({ service_policy_oid: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("service_policy_oid.missing"), out.errors.join("|"));
});

test("issuance: invalid service_recipient_commit -> service_recipient_commit.invalid", () => {
  const out = verifyAarBody(issuance({ service_recipient_commit: "not-a-hash" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("service_recipient_commit.invalid"), out.errors.join("|"));
});

test("issuance: invalid artefact_metadata_commit -> artefact_metadata_commit.invalid", () => {
  const out = verifyAarBody(issuance({ artefact_metadata_commit: "bad" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("artefact_metadata_commit.invalid"), out.errors.join("|"));
});

// ── Issuance: artefact_hash conditional ──────────────────────────────────────

test("issuance: qes missing artefact_hash -> artefact_hash.required_for_service_type", () => {
  const out = verifyAarBody(qesIssuance({ artefact_hash: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("artefact_hash.required_for_service_type"), out.errors.join("|"));
});

test("issuance: qeseal missing artefact_hash -> artefact_hash.required_for_service_type", () => {
  const out = verifyAarBody(issuance({
    service_type: "qeseal",
    artefact_hash: null,
    signature_format: "cades_b_lta",
    qcert_serial_commit: SHA(22),
  }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("artefact_hash.required_for_service_type"), out.errors.join("|"));
});

test("issuance: qereg missing artefact_hash -> artefact_hash.required_for_service_type", () => {
  const out = verifyAarBody(issuance({ service_type: "qereg", artefact_hash: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("artefact_hash.required_for_service_type"), out.errors.join("|"));
});

test("issuance: qwallet null artefact_hash is allowed", () => {
  const out = verifyAarBody(issuance({ service_type: "qwallet", artefact_hash: null }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("issuance: qattest null artefact_hash is allowed", () => {
  const out = verifyAarBody(issuance({ service_type: "qattest", artefact_hash: null }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("issuance: qwallet with invalid non-null artefact_hash -> artefact_hash.invalid", () => {
  const out = verifyAarBody(issuance({ service_type: "qwallet", artefact_hash: "bad-hash" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("artefact_hash.invalid"), out.errors.join("|"));
});

// ── Issuance: signature_format conditional ────────────────────────────────────

test("issuance: qes missing signature_format -> signature_format.required_for_service_type", () => {
  const out = verifyAarBody(qesIssuance({ signature_format: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("signature_format.required_for_service_type"), out.errors.join("|"));
});

test("issuance: qes invalid signature_format -> signature_format.invalid", () => {
  const out = verifyAarBody(qesIssuance({ signature_format: "pdf" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("signature_format.invalid"), out.errors.join("|"));
});

test("issuance: qwallet null signature_format is allowed", () => {
  const out = verifyAarBody(issuance({ service_type: "qwallet", signature_format: null }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("issuance: qts with non-null invalid signature_format -> signature_format.invalid", () => {
  const out = verifyAarBody(issuance({
    service_type: "qts",
    artefact_hash: SHA(30),
    signature_format: "not_a_format",
  }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("signature_format.invalid"), out.errors.join("|"));
});

// ── Issuance: qcert_serial_commit conditional ─────────────────────────────────

test("issuance: qes missing qcert_serial_commit -> qcert_serial_commit.required_for_service_type", () => {
  const out = verifyAarBody(qesIssuance({ qcert_serial_commit: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("qcert_serial_commit.required_for_service_type"), out.errors.join("|"));
});

test("issuance: qcert_natural missing qcert_serial_commit -> qcert_serial_commit.required_for_service_type", () => {
  const out = verifyAarBody(issuance({ service_type: "qcert_natural", qcert_serial_commit: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("qcert_serial_commit.required_for_service_type"), out.errors.join("|"));
});

test("issuance: qcert_legal requires qcert_serial_commit", () => {
  const out = verifyAarBody(issuance({ service_type: "qcert_legal", qcert_serial_commit: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("qcert_serial_commit.required_for_service_type"), out.errors.join("|"));
});

test("issuance: qts does not require qcert_serial_commit", () => {
  const out = verifyAarBody(issuance({
    service_type: "qts",
    artefact_hash: SHA(20),
    qcert_serial_commit: null,
  }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

// ── Issuance: atr_transfer_hash optional ─────────────────────────────────────

test("issuance: valid atr_transfer_hash -> valid", () => {
  const out = verifyAarBody(issuance({ atr_transfer_hash: SHA(50) }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("issuance: invalid non-null atr_transfer_hash -> atr_transfer_hash.invalid", () => {
  const out = verifyAarBody(issuance({ atr_transfer_hash: "not-sha256" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("atr_transfer_hash.invalid"), out.errors.join("|"));
});

// ── TSL field validation (issuance) ──────────────────────────────────────────

test("issuance: invalid tsl_country -> tsl_country.invalid", () => {
  const out = verifyAarBody(issuance({ tsl_country: "de" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_country.invalid"), out.errors.join("|"));
});

test("issuance: tsl_country 3 chars -> tsl_country.invalid", () => {
  const out = verifyAarBody(issuance({ tsl_country: "DEU" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_country.invalid"), out.errors.join("|"));
});

test("issuance: missing tsl_entry_hash -> tsl_entry_hash.missing", () => {
  const out = verifyAarBody(issuance({ tsl_entry_hash: "not-sha256" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_entry_hash.missing"), out.errors.join("|"));
});

test("issuance: missing tsl_signed_tree_head_root -> tsl_signed_tree_head_root.missing", () => {
  const out = verifyAarBody(issuance({ tsl_signed_tree_head_root: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_signed_tree_head_root.missing"), out.errors.join("|"));
});

test("issuance: non-array tsl_inclusion_proof -> tsl_inclusion_proof.invalid", () => {
  const out = verifyAarBody(issuance({ tsl_inclusion_proof: "not-array" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_inclusion_proof.invalid"), out.errors.join("|"));
});

test("issuance: invalid entry in tsl_inclusion_proof -> indexed error", () => {
  const out = verifyAarBody(issuance({ tsl_inclusion_proof: [SHA(3), "bad-entry"] }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_inclusion_proof[1].invalid"), out.errors.join("|"));
});

test("issuance: negative tsl_tree_size -> tsl_tree_size.invalid", () => {
  const out = verifyAarBody(issuance({ tsl_tree_size: -1 }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_tree_size.invalid"), out.errors.join("|"));
});

test("issuance: non-integer tsl_tree_size -> tsl_tree_size.invalid", () => {
  const out = verifyAarBody(issuance({ tsl_tree_size: 1.5 }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_tree_size.invalid"), out.errors.join("|"));
});

test("issuance: zero tsl_tree_size is allowed", () => {
  const out = verifyAarBody(issuance({ tsl_tree_size: 0 }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("issuance: invalid tsl_log_time date string -> tsl_log_time.invalid", () => {
  const out = verifyAarBody(issuance({ tsl_log_time: "not-a-date" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_log_time.invalid"), out.errors.join("|"));
});

test("issuance: empty tsl_log_time -> tsl_log_time.invalid", () => {
  const out = verifyAarBody(issuance({ tsl_log_time: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_log_time.invalid"), out.errors.join("|"));
});

// ── Revocation: reason ────────────────────────────────────────────────────────

test("revocation: invalid reason -> reason.invalid", () => {
  const out = verifyAarBody(revocation({ reason: "expired" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("reason.invalid"), out.errors.join("|"));
});

test("revocation: null reason -> reason.invalid", () => {
  const out = verifyAarBody(revocation({ reason: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("reason.invalid"), out.errors.join("|"));
});

test("revocation: all valid reasons accepted", () => {
  const reasons = ["key_compromise", "policy_violation", "recipient_request",
    "controller_decision", "tsl_delisted", "superseded"];
  for (const reason of reasons) {
    const out = verifyAarBody(revocation({ reason }));
    assert.equal(out.valid, true, `reason=${reason}: ${out.errors.join("|")}`);
  }
});

// ── Revocation: reason_ref_hash optional ─────────────────────────────────────

test("revocation: invalid non-null reason_ref_hash -> reason_ref_hash.invalid", () => {
  const out = verifyAarBody(revocation({ reason_ref_hash: "bad-hash" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("reason_ref_hash.invalid"), out.errors.join("|"));
});

test("revocation: null reason_ref_hash allowed", () => {
  const out = verifyAarBody(revocation({ reason_ref_hash: null }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

// ── TSL field validation (revocation) ────────────────────────────────────────

test("revocation: invalid tsl_country -> tsl_country.invalid", () => {
  const out = verifyAarBody(revocation({ tsl_country: "xx" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_country.invalid"), out.errors.join("|"));
});

test("revocation: missing tsl_entry_hash -> tsl_entry_hash.missing", () => {
  const out = verifyAarBody(revocation({ tsl_entry_hash: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_entry_hash.missing"), out.errors.join("|"));
});

test("revocation: non-array tsl_inclusion_proof -> tsl_inclusion_proof.invalid", () => {
  const out = verifyAarBody(revocation({ tsl_inclusion_proof: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_inclusion_proof.invalid"), out.errors.join("|"));
});

test("revocation: invalid tsl_log_time -> tsl_log_time.invalid", () => {
  const out = verifyAarBody(revocation({ tsl_log_time: "not-a-date" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_log_time.invalid"), out.errors.join("|"));
});

test("revocation: negative tsl_tree_size -> tsl_tree_size.invalid", () => {
  const out = verifyAarBody(revocation({ tsl_tree_size: -5 }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("tsl_tree_size.invalid"), out.errors.join("|"));
});
