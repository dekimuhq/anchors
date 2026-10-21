import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { canonicalize, base64UrlEncode } from "../src/index.ts";
import { verifySingleReceipt } from "../src/index.ts";
import type { ARRReceipt } from "../src/index.ts";

function makeReceipt(overrides: Partial<ARRReceipt> = {}): ARRReceipt {
  return {
    kind: "ar.erasure.v1",
    profile: "gdpr.art17",
    iss: "did:web:bank.example",
    iss_key: "ed25519:placeholder",
    target_kind: "subject",
    target_commit: "sha256:" + "ab".repeat(32),
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "cd".repeat(32),
    policy_uri: "https://bank.example/p/v3",
    policy_version: "3.1.0",
    trigger: "subject_request",
    trigger_receipt: "sha256:" + "ef".repeat(32),
    event_at: "2026-05-16T09:12:00Z",
    granted_at: "2026-05-16T09:14:00Z",
    effective_until: null,
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: "sha256:" + "cd".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
    prev: null,
    field_root: "sha256:" + "11".repeat(32),
    anchor: null,
    sig: null,
    ...overrides,
  };
}

function signReceipt(r: ARRReceipt): { receipt: ARRReceipt; pubKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = spki.subarray(spki.length - 32);
  const pubB64 = base64UrlEncode(rawPub);
  const r2: ARRReceipt = { ...r, iss_key: `ed25519:${pubB64}`, sig: null, anchor: null };
  const msg = new TextEncoder().encode(canonicalize(r2));
  const sigBytes = nodeSign(null, msg, privateKey);
  return {
    receipt: { ...r2, sig: `ed25519:${base64UrlEncode(sigBytes)}` },
    pubKey: `ed25519:${pubB64}`,
  };
}

test("valid signature with anchor inclusion time after event_at + granted_at -> valid", () => {
  const { receipt } = signReceipt(makeReceipt());
  const out = verifySingleReceipt(receipt, {
    anchorInclusionTime: "2026-05-16T09:15:00Z",
  });
  assert.equal(out.valid, true);
  assert.deepEqual(out.errors, []);
});

test("event_at after anchor inclusion -> invalid", () => {
  const { receipt } = signReceipt(makeReceipt({ event_at: "2099-01-01T00:00:00Z" }));
  const out = verifySingleReceipt(receipt, {
    anchorInclusionTime: "2026-05-16T09:15:00Z",
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_at.after.anchor"));
});

test("granted_at after anchor inclusion -> invalid", () => {
  const { receipt } = signReceipt(makeReceipt({ granted_at: "2099-01-01T00:00:00Z" }));
  const out = verifySingleReceipt(receipt, {
    anchorInclusionTime: "2026-05-16T09:15:00Z",
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("granted_at.after.anchor"));
});

test("event_at after granted_at with strictSelfConsistency -> invalid", () => {
  const { receipt } = signReceipt(makeReceipt({
    granted_at: "2026-05-16T08:00:00Z",
    event_at: "2026-05-16T09:00:00Z",
  }));
  const out = verifySingleReceipt(receipt, {
    anchorInclusionTime: "2026-05-16T09:15:00Z",
    strictSelfConsistency: true,
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_at.after.granted_at"));
});

test("tampered field invalidates signature", () => {
  const { receipt } = signReceipt(makeReceipt());
  const tampered: ARRReceipt = { ...receipt, policy_version: "999.0.0" };
  const out = verifySingleReceipt(tampered, {
    anchorInclusionTime: "2026-05-16T09:15:00Z",
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.some((e) => e.startsWith("sig.")));
});

test("missing sig -> invalid", () => {
  const r = makeReceipt();
  const out = verifySingleReceipt(r, { anchorInclusionTime: "2026-05-16T09:15:00Z" });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("sig.missing"));
});

test("subject_request trigger without trigger_receipt -> invalid", () => {
  const { receipt } = signReceipt(makeReceipt({ trigger_receipt: null }));
  const out = verifySingleReceipt(receipt, {
    anchorInclusionTime: "2026-05-16T09:15:00Z",
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("trigger_receipt.required"));
});
