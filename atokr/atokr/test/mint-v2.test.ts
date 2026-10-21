/**
 * Tests for mintAtokrV2 — covers all 4 event types, validation guards,
 * and round-trip verification.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAtokrV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { anchor, baseCommon, H, makeResolveKey, makeSigningKey, scope } from "./_helpers/common.ts";

// ── V1: guard — issuer required ───────────────────────────────────────────────

test("V1: throws when issuer missing", async () => {
  await assert.rejects(
    () =>
      mintAtokrV2({
        ...baseCommon,
        issuer: "",
        signingKey: makeSigningKey(),
        event_type: "token.issued",
        token_id: "tok-001",
        format_class: "pan",
        scope,
      }),
    /issuer required/,
  );
});

// ── V2: guard — signingKey.kid required ──────────────────────────────────────

test("V2: throws when signingKey.kid missing", async () => {
  await assert.rejects(
    () =>
      mintAtokrV2({
        ...baseCommon,
        signingKey: { kid: "", privateKey: new Uint8Array(32) },
        event_type: "token.issued",
        token_id: "tok-001",
        format_class: "pan",
        scope,
      }),
    /signingKey\.kid required/,
  );
});

// ── V3: guard — private key must be 32 bytes ──────────────────────────────────

test("V3: throws when private key seed is wrong length", async () => {
  await assert.rejects(
    () =>
      mintAtokrV2({
        ...baseCommon,
        signingKey: { kid: "k", privateKey: new Uint8Array(16) },
        event_type: "token.issued",
        token_id: "tok-001",
        format_class: "pan",
        scope,
      }),
    /must be 32 bytes/,
  );
});

// ── V4: guard — subject must be sha256:<hex> ──────────────────────────────────

test("V4: throws when subject is not sha256:<hex>", async () => {
  await assert.rejects(
    () =>
      mintAtokrV2({
        ...baseCommon,
        subject: "not-a-hash",
        signingKey: makeSigningKey(),
        event_type: "token.issued",
        token_id: "tok-001",
        format_class: "pan",
        scope,
      }),
    /sha256/,
  );
});

// ── V5: guard — token.issued prev must be null ────────────────────────────────

test("V5: throws when token.issued has non-null prev", async () => {
  await assert.rejects(
    () =>
      mintAtokrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "token.issued",
        token_id: "tok-001",
        format_class: "pan",
        scope,
        prev: "01HPREV0000000000000000",
      }),
    /chain head/,
  );
});

// ── V6: guard — token.rotated requires rotation_of ───────────────────────────

test("V6: throws when token.rotated has empty rotation_of", async () => {
  await assert.rejects(
    () =>
      mintAtokrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "token.rotated",
        token_id: "tok-002",
        format_class: "pan",
        scope,
        rotation_of: "",
      }),
    /rotation_of/,
  );
});

// ── V7: token.issued produces v=2 receipt with correct claim_type and sig ────

test("V7: token.issued produces v=2 receipt with correct claim_type", async () => {
  const env = await mintAtokrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "token.issued",
    token_id: "tok-001",
    format_class: "email",
    scope,
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.tokenization.v1");
  assert.ok(env.sig.length > 0);
  assert.equal((env.body as { event_type: string }).event_type, "token.issued");
});

// ── V8: token.issued round-trips through verifyReceipt ───────────────────────

test("V8: token.issued round-trips through verifyReceipt", async () => {
  const signingKey = makeSigningKey();
  const env = await mintAtokrV2({
    ...baseCommon,
    signingKey,
    event_type: "token.issued",
    token_id: "tok-rt-001",
    format_class: "iban",
    scope,
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V9: token.redeemed produces valid receipt ─────────────────────────────────

test("V9: token.redeemed produces valid receipt", async () => {
  const env = await mintAtokrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "token.redeemed",
    token_id: "tok-001",
    scope,
    prev: "01HISSUED000000000000000",
  });
  assert.equal(env.v, 2);
  assert.equal((env.body as { event_type: string }).event_type, "token.redeemed");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V10: token.revoked produces valid receipt ─────────────────────────────────

test("V10: token.revoked produces valid receipt", async () => {
  const env = await mintAtokrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "token.revoked",
    token_id: "tok-001",
    scope,
    prev: "01HISSUED000000000000000",
  });
  assert.equal(env.v, 2);
  assert.equal((env.body as { event_type: string }).event_type, "token.revoked");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V11: token.rotated includes rotation_of in body ──────────────────────────

test("V11: token.rotated includes rotation_of in body", async () => {
  const env = await mintAtokrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "token.rotated",
    token_id: "tok-002",
    format_class: "pan",
    scope,
    rotation_of: "01HISSUED000000000000000",
  });
  const body = env.body as { event_type: string; rotation_of: string };
  assert.equal(body.event_type, "token.rotated");
  assert.equal(body.rotation_of, "01HISSUED000000000000000");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V12: token.issued body carries field_root ─────────────────────────────────

test("V12: token.issued body carries field_root", async () => {
  const env = await mintAtokrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "token.issued",
    token_id: "tok-fr-001",
    format_class: "phone",
    scope,
  });
  const body = env.body as Record<string, unknown>;
  assert.ok(typeof body["field_root"] === "string");
  assert.ok((body["field_root"] as string).startsWith("sha256:"));
});

// ── V13: token.issued with pci_environment profile field ──────────────────────

test("V13: token.issued with pci_environment field passes verification", async () => {
  const env = await mintAtokrV2({
    ...baseCommon,
    profile: "tokenization.pci.dss_v4",
    signingKey: makeSigningKey(),
    event_type: "token.issued",
    token_id: "tok-pci-001",
    format_class: "pan",
    scope,
    pci_environment: "cde",
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  const body = env.body as Record<string, unknown>;
  assert.equal(body["pci_environment"], "cde");
});

// ── V14: token.redeemed with optional redemption_audit_ref ───────────────────

test("V14: token.redeemed with redemption_audit_ref round-trips", async () => {
  const env = await mintAtokrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "token.redeemed",
    token_id: "tok-001",
    scope,
    redemption_audit_ref: "asr-ref-01HABC000",
    prev: "01HISSUED000000000000000",
  });
  const body = env.body as { redemption_audit_ref: string | null };
  assert.equal(body.redemption_audit_ref, "asr-ref-01HABC000");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V15: envelope carries anchor from input ───────────────────────────────────

test("V15: envelope carries anchor and policy fields from input", async () => {
  const env = await mintAtokrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "token.issued",
    token_id: "tok-anchor-001",
    format_class: "national_id",
    scope,
  });
  assert.deepEqual(env.anchor, anchor);
  assert.equal(env.policy_uri, baseCommon.policy_uri);
  assert.equal(env.iss, baseCommon.issuer);
});

// ── T_QTS: non-null qts_attestation_hash round-trips ────────────────────────

test("T_QTS: non-null qts_attestation_hash round-trips through verifier", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintAtokrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "token.issued",
    token_id: "tok-qts-001",
    format_class: "pan",
    scope,
    qts_attestation_hash: QTS,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
