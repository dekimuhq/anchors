/**
 * Tests for mintAerV2 — covers both event types, validation guards,
 * and round-trip verification.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAerV2 } from "../src/issue/mint-v2.ts";
import {
  issueContinuityAttestation,
  verifyContinuityAttestation,
} from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import {
  anchor,
  baseConformityInput,
  baseTransparencyInput,
  H,
  makeResolveKey,
  makeSigningKey,
} from "./_helpers/issue-fixtures.ts";

// ── V1: conformity receipt with null subject — mints and round-trips ──────────

test("V1: mints conformity receipt with null subject and verifies", async () => {
  const signingKey = makeSigningKey();
  const env = await mintAerV2({
    ...baseConformityInput,
    signingKey,
    event_type: "conformity",
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.evaluation.v1");
  assert.equal(env.subject, null, "conformity subject must be null");
  assert.equal((env.body as { event_type: string }).event_type, "conformity");
  assert.ok(env.sig.length > 0);

  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V2: transparency receipt with sha256 subject — mints and round-trips ──────

test("V2: mints transparency receipt with sha256 subject and verifies", async () => {
  const signingKey = makeSigningKey();
  const env = await mintAerV2({
    ...baseTransparencyInput,
    signingKey,
    event_type: "transparency",
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.evaluation.v1");
  assert.equal(env.subject, baseTransparencyInput.subject);
  assert.equal((env.body as { event_type: string }).event_type, "transparency");
  assert.ok(env.sig.length > 0);

  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V3: guard — issuer required ───────────────────────────────────────────────

test("V3: throws when issuer missing", async () => {
  await assert.rejects(
    () =>
      mintAerV2({
        ...baseConformityInput,
        issuer: "",
        signingKey: makeSigningKey(),
        event_type: "conformity",
      }),
    /issuer required/,
  );
});

// ── V4: guard — transparency without sha256 subject ───────────────────────────

test("V4: throws on transparency without sha256 subject", async () => {
  await assert.rejects(
    () =>
      mintAerV2({
        ...baseTransparencyInput,
        subject: "not-a-hash",
        signingKey: makeSigningKey(),
        event_type: "transparency",
      }),
    /sha256/,
  );
});

// ── V5: conformity body carries field_root ────────────────────────────────────

test("V5: conformity body carries field_root", async () => {
  const env = await mintAerV2({
    ...baseConformityInput,
    signingKey: makeSigningKey(),
    event_type: "conformity",
  });
  const body = env.body as Record<string, unknown>;
  assert.ok(typeof body["field_root"] === "string");
  assert.ok((body["field_root"] as string).startsWith("sha256:"));
});

// ── V6: transparency body carries field_root ──────────────────────────────────

test("V6: transparency body carries field_root", async () => {
  const env = await mintAerV2({
    ...baseTransparencyInput,
    signingKey: makeSigningKey(),
    event_type: "transparency",
  });
  const body = env.body as Record<string, unknown>;
  assert.ok(typeof body["field_root"] === "string");
  assert.ok((body["field_root"] as string).startsWith("sha256:"));
});

// ── V7: conformity carries anchor from input ──────────────────────────────────

test("V7: conformity envelope carries anchor and issuer from input", async () => {
  const env = await mintAerV2({
    ...baseConformityInput,
    signingKey: makeSigningKey(),
    event_type: "conformity",
  });
  assert.deepEqual(env.anchor, anchor);
  assert.equal(env.iss, baseConformityInput.issuer);
});

// ── V8: transparency body fields preserved ────────────────────────────────────

test("V8: transparency body fields preserved in envelope", async () => {
  const env = await mintAerV2({
    ...baseTransparencyInput,
    signingKey: makeSigningKey(),
    event_type: "transparency",
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body["disclosure_type"], "chatbot");
  assert.equal(body["watermark_scheme"], "none");
  assert.equal(body["disclosure_locale"], "en");
});

// ── V9: guard — signingKey.kid required ──────────────────────────────────────

test("V9: throws when signingKey.kid missing", async () => {
  await assert.rejects(
    () =>
      mintAerV2({
        ...baseConformityInput,
        signingKey: { kid: "", privateKey: new Uint8Array(32) },
        event_type: "conformity",
      }),
    /signingKey\.kid required/,
  );
});

// ── V10: guard — private key must be 32 bytes ─────────────────────────────────

test("V10: throws when private key seed is wrong length", async () => {
  await assert.rejects(
    () =>
      mintAerV2({
        ...baseConformityInput,
        signingKey: { kid: "k", privateKey: new Uint8Array(16) },
        event_type: "conformity",
      }),
    /must be 32 bytes/,
  );
});

// ── V11: conformity default kind is "observation" ────────────────────────────

test("V11: conformity default envelope_kind is observation", async () => {
  const env = await mintAerV2({
    ...baseConformityInput,
    signingKey: makeSigningKey(),
    event_type: "conformity",
  });
  assert.equal(env.kind, "observation");
});

// ── V12: transparency with optional fields ────────────────────────────────────

test("V12: transparency with artifact_apr_hash and oversight_acr_hash round-trips", async () => {
  const env = await mintAerV2({
    ...baseTransparencyInput,
    signingKey: makeSigningKey(),
    event_type: "transparency",
    artifact_apr_hash: H("a"),
    oversight_acr_hash: H("o"),
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body["artifact_apr_hash"], H("a"));
  assert.equal(body["oversight_acr_hash"], H("o"));
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V13: continuity re-exports are callable ───────────────────────────────────

test("V13: re-exports continuity helpers", () => {
  assert.strictEqual(typeof issueContinuityAttestation, "function");
  assert.strictEqual(typeof verifyContinuityAttestation, "function");
});

// ── T_QTS: non-null qts_attestation_hash round-trips ────────────────────────

test("T_QTS: non-null qts_attestation_hash round-trips through verifier", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintAerV2({
    ...baseConformityInput,
    signingKey: makeSigningKey(),
    event_type: "conformity",
    qts_attestation_hash: QTS,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
