/**
 * Tests for mintAarV2 — covers both event types, validation guards,
 * and round-trip verification.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAarV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { anchor, baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

// qes requires: artefact_hash (sha256), signature_format, qcert_serial_commit
const baseIssuance = {
  service_type: "qes" as const,
  service_policy_oid: "0.4.0.1862.1.1",
  service_recipient_commit: "sha256:" + "b".repeat(64),
  artefact_hash: "sha256:" + "a".repeat(64),
  artefact_metadata_commit: "sha256:" + "c".repeat(64),
  signature_format: "pades_b_lta" as const,
  qcert_serial_commit: "sha256:" + "9".repeat(64),
  tsl_country: "ES",
  tsl_entry_hash: "sha256:" + "d".repeat(64),
  tsl_signed_tree_head_root: "sha256:" + "f".repeat(64),
  tsl_tree_size: 42,
  tsl_inclusion_proof: ["sha256:" + "1".repeat(64)],
  tsl_log_time: "2026-05-16T10:00:00Z",
};

// ── V1: mints valid issuance receipt ─────────────────────────────────────────

test("V1: mints valid issuance receipt (v=2, claim_type, sig, prev=null, round-trip)", async () => {
  const signingKey = makeSigningKey();
  const env = await mintAarV2({
    ...baseCommon,
    signingKey,
    event_type: "issuance",
    ...baseIssuance,
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.attestation.v1");
  assert.ok(env.sig.length > 0);
  assert.equal(env.prev, null);
  assert.equal((env.body as { event_type: string }).event_type, "issuance");

  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V2: mints valid revocation receipt ───────────────────────────────────────

test("V2: mints valid revocation receipt (prev set, round-trip passes)", async () => {
  const signingKey = makeSigningKey();
  const env = await mintAarV2({
    ...baseCommon,
    signingKey,
    event_type: "revocation",
    prev: "01HISSUANCE00000000000000",
    reason: "key_compromise",
    tsl_country: "ES",
    tsl_entry_hash: "sha256:" + "d".repeat(64),
    tsl_signed_tree_head_root: "sha256:" + "f".repeat(64),
    tsl_tree_size: 42,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-16T12:00:00Z",
  });
  assert.equal(env.v, 2);
  assert.equal((env.body as { event_type: string }).event_type, "revocation");
  assert.equal(env.prev, "01HISSUANCE00000000000000");

  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V3: rejects issuance with prev set ───────────────────────────────────────

test("V3: rejects issuance with prev set", async () => {
  await assert.rejects(
    () =>
      mintAarV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "issuance",
        ...baseIssuance,
        prev: "01HISSUANCE00000000000000",
      }),
    /issuance must have prev=null/,
  );
});

// ── V4: rejects revocation without prev ──────────────────────────────────────

test("V4: rejects revocation without prev", async () => {
  await assert.rejects(
    () =>
      mintAarV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "revocation",
        reason: "policy_violation",
        tsl_country: "ES",
        tsl_entry_hash: "sha256:" + "d".repeat(64),
        tsl_signed_tree_head_root: "sha256:" + "f".repeat(64),
        tsl_tree_size: 1,
        tsl_inclusion_proof: [],
        tsl_log_time: "2026-05-16T12:00:00Z",
      }),
    /revocation must have prev/,
  );
});

// ── V5: rejects invalid subject ───────────────────────────────────────────────

test("V5: rejects subject not matching sha256:<hex>", async () => {
  await assert.rejects(
    () =>
      mintAarV2({
        ...baseCommon,
        subject: "not-a-hash",
        signingKey: makeSigningKey(),
        event_type: "issuance",
        ...baseIssuance,
      }),
    /sha256/,
  );
});

// ── V6: defaults kind to "decision" ──────────────────────────────────────────

test("V6: defaults envelope kind to 'decision'", async () => {
  const env = await mintAarV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "issuance",
    ...baseIssuance,
  });
  assert.equal(env.kind, "decision");
});

// ── V7: body carries field_root ───────────────────────────────────────────────

test("V7: issuance body carries field_root", async () => {
  const env = await mintAarV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "issuance",
    ...baseIssuance,
  });
  const body = env.body as Record<string, unknown>;
  assert.ok(typeof body["field_root"] === "string");
  assert.ok((body["field_root"] as string).startsWith("sha256:"));
});

// ── V8: envelope carries anchor and policy fields from input ──────────────────

test("V8: envelope carries anchor and policy fields from input", async () => {
  const env = await mintAarV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "issuance",
    ...baseIssuance,
  });
  assert.deepEqual(env.anchor, anchor);
  assert.equal(env.policy_uri, baseCommon.policy_uri);
  assert.equal(env.iss, baseCommon.issuer);
});

// ── T_QTS: non-null qts_attestation_hash round-trips ────────────────────────

test("T_QTS: non-null qts_attestation_hash round-trips through verifier", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintAarV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "issuance",
    ...baseIssuance,
    qts_attestation_hash: QTS,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
