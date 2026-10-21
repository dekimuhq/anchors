/**
 * Tests for the six per-event convenience wrappers in mint-single.ts.
 * Each wrapper produces a receipt the verifier accepts and carries the
 * correct `event` discriminator in the body.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  mintGrant,
  mintRevoke,
  mintNarrow,
  mintRenew,
  mintSuspend,
  mintResume,
} from "../src/issue/index.ts";
import { adrFamily } from "../src/index.ts";
import {
  baseCommon,
  defaultAgent,
  defaultScope,
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

// ── S1: mintGrant round-trips ─────────────────────────────────────────────────

test("S1: mintGrant round-trips", async () => {
  const env = await mintGrant({
    ...baseCommon,
    signingKey: makeSigningKey(),
    ...baseGrant,
  });
  assert.equal((env.body as { event: string }).event, "grant");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S2: mintRevoke round-trips ────────────────────────────────────────────────

test("S2: mintRevoke round-trips", async () => {
  const env = await mintRevoke({
    ...baseCommon,
    signingKey: makeSigningKey(),
    prev: "01HGRANT000000000000000",
  });
  assert.equal((env.body as { event: string }).event, "revoke");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S3: mintNarrow round-trips ────────────────────────────────────────────────

test("S3: mintNarrow round-trips", async () => {
  const env = await mintNarrow({
    ...baseCommon,
    signingKey: makeSigningKey(),
    prev: "01HGRANT000000000000000",
    scope: {
      actions: ["invoice.create"],
      resources: ["acme:customer:acme-corp"],
      constraints: {},
    },
  });
  assert.equal((env.body as { event: string }).event, "narrow");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S4: mintRenew round-trips ─────────────────────────────────────────────────

test("S4: mintRenew round-trips", async () => {
  const env = await mintRenew({
    ...baseCommon,
    signingKey: makeSigningKey(),
    prev: "01HGRANT000000000000000",
    expiry: Date.now() + 86400 * 1000 * 30,
  });
  assert.equal((env.body as { event: string }).event, "renew");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S5: mintSuspend round-trips ───────────────────────────────────────────────

test("S5: mintSuspend round-trips", async () => {
  const env = await mintSuspend({
    ...baseCommon,
    signingKey: makeSigningKey(),
    prev: "01HGRANT000000000000000",
    cascade: false,
  });
  assert.equal((env.body as { event: string }).event, "suspend");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S6: mintResume round-trips ────────────────────────────────────────────────

test("S6: mintResume round-trips", async () => {
  const env = await mintResume({
    ...baseCommon,
    signingKey: makeSigningKey(),
    prev: "01HSUSPEND00000000000000",
  });
  assert.equal((env.body as { event: string }).event, "resume");
  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
