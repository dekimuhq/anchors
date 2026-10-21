/**
 * Tests for mintAdrV2 — covers all 6 event types, validation guards,
 * and round-trip verification.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAdrV2 } from "../src/issue/mint-v2.ts";
import { adrFamily } from "../src/index.ts";
import {
  anchor,
  baseCommon,
  defaultAgent,
  defaultScope,
  H,
  makeResolveKey,
  makeSigningKey,
} from "./_helpers/issue-common.ts";

const baseGrant = {
  agent: defaultAgent,
  scope: defaultScope,
  delegable: false,
  expiry: null,
  rationale_uri: "https://acme.example/rationale/v1",
  rationale_hash: "sha256:" + "f".repeat(64),
};

// ── V1: guard — issuer required ───────────────────────────────────────────────

test("V1: throws when issuer missing", async () => {
  await assert.rejects(
    () =>
      mintAdrV2({
        ...baseCommon,
        issuer: "",
        signingKey: makeSigningKey(),
        event: "grant",
        ...baseGrant,
      }),
    /issuer required/,
  );
});

// ── V2: guard — signingKey.kid required ──────────────────────────────────────

test("V2: throws when signingKey.kid missing", async () => {
  await assert.rejects(
    () =>
      mintAdrV2({
        ...baseCommon,
        signingKey: { kid: "", privateKey: new Uint8Array(32) },
        event: "grant",
        ...baseGrant,
      }),
    /signingKey\.kid required/,
  );
});

// ── V3: guard — private key must be 32 bytes ──────────────────────────────────

test("V3: throws when private key seed is wrong length", async () => {
  await assert.rejects(
    () =>
      mintAdrV2({
        ...baseCommon,
        signingKey: { kid: "k", privateKey: new Uint8Array(16) },
        event: "grant",
        ...baseGrant,
      }),
    /must be 32 bytes/,
  );
});

// ── V4: guard — subject must be sha256:<hex> ──────────────────────────────────

test("V4: throws when subject is not sha256:<hex>", async () => {
  await assert.rejects(
    () =>
      mintAdrV2({
        ...baseCommon,
        subject: "not-a-hash",
        signingKey: makeSigningKey(),
        event: "grant",
        ...baseGrant,
      }),
    /sha256/,
  );
});

// ── V5: grant produces v=2 receipt with correct claim_type ───────────────────

test("V5: grant produces v=2 receipt with correct claim_type", async () => {
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "grant",
    ...baseGrant,
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.delegation.v1");
  assert.ok(env.sig.length > 0);
  assert.equal((env.body as { event: string }).event, "grant");
});

// ── V6: grant round-trips through adrFamily.verifyReceipt ────────────────────

test("V6: grant round-trips through adrFamily.verifyReceipt", async () => {
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "grant",
    ...baseGrant,
  });
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V7: revoke produces valid receipt ─────────────────────────────────────────

test("V7: revoke produces valid receipt", async () => {
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "revoke",
    prev: "01HGRANT000000000000000",
    reason_uri: "https://acme.example/policy/revocation",
    reason_hash: "sha256:" + "a".repeat(64),
  });
  assert.equal(env.v, 2);
  assert.equal((env.body as { event: string }).event, "revoke");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V8: narrow produces valid receipt ─────────────────────────────────────────

test("V8: narrow produces valid receipt", async () => {
  const narrowedScope = {
    actions: ["invoice.create"],
    resources: ["acme:customer:acme-corp"],
    constraints: { max_amount_eur: 1000 },
  };
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "narrow",
    prev: "01HGRANT000000000000000",
    scope: narrowedScope,
  });
  assert.equal(env.v, 2);
  assert.equal((env.body as { event: string }).event, "narrow");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V9: renew produces valid receipt ──────────────────────────────────────────

test("V9: renew produces valid receipt", async () => {
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "renew",
    prev: "01HGRANT000000000000000",
    expiry: Date.now() + 86400 * 1000 * 90,
  });
  assert.equal(env.v, 2);
  assert.equal((env.body as { event: string }).event, "renew");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V10: suspend produces valid receipt ──────────────────────────────────────

test("V10: suspend produces valid receipt", async () => {
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "suspend",
    prev: "01HGRANT000000000000000",
    reason_uri: "https://acme.example/policy/suspension",
    cascade: true,
  });
  assert.equal(env.v, 2);
  assert.equal((env.body as { event: string }).event, "suspend");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V11: resume produces valid receipt ───────────────────────────────────────

test("V11: resume produces valid receipt", async () => {
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "resume",
    prev: "01HSUSPEND00000000000000",
  });
  assert.equal(env.v, 2);
  assert.equal((env.body as { event: string }).event, "resume");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V12: grant body carries field_root ────────────────────────────────────────

test("V12: grant body carries field_root", async () => {
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "grant",
    ...baseGrant,
  });
  const body = env.body as Record<string, unknown>;
  assert.ok(typeof body["field_root"] === "string");
  assert.ok((body["field_root"] as string).startsWith("sha256:"));
});

// ── V13: envelope carries anchor and policy fields ────────────────────────────

test("V13: envelope carries anchor and policy fields from input", async () => {
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "grant",
    ...baseGrant,
  });
  assert.deepEqual(env.anchor, anchor);
  assert.equal(env.policy_uri, baseCommon.policy_uri);
  assert.equal(env.iss, baseCommon.issuer);
});

// ── V14: defaults envelope kind to "decision" ─────────────────────────────────

test("V14: defaults envelope kind to 'decision'", async () => {
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "grant",
    ...baseGrant,
  });
  assert.equal(env.kind, "decision");
});

// ── T_QTS: non-null qts_attestation_hash round-trips ────────────────────────

test("T_QTS: non-null qts_attestation_hash round-trips through verifier", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintAdrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event: "grant",
    ...baseGrant,
    qts_attestation_hash: QTS,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
