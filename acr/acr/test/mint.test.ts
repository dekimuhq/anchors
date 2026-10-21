import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeypair,
  encodeRaw,
  type Keypair,
} from "../src/issue/keys.ts";
import { mintConsent, mintModification, mintWithdrawal } from "../src/issue/mint.ts";
import {
  verifyReceiptSignature,
  resolveChainState,
  hashReceipt,
} from "../src/index.ts";

function signingKey(): Keypair {
  return generateKeypair("test-issuer-key");
}

test("mintConsent produces a valid, self-verifying consent receipt", () => {
  const key = signingKey();
  const receipt = mintConsent({
    issuerDid: "did:web:bank.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "alice@example.com" },
      purposes: [{ value: "marketing-emails" }],
      policy_hash: { value: "policy-v3" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
  });

  assert.equal(receipt.kind, "ar.consent.v1");
  assert.equal(receipt.profile, "gdpr.art7");
  assert.equal(receipt.iss, "did:web:bank.example");
  assert.equal(receipt.iss_key, `ed25519:${encodeRaw(key.publicKey)}`);
  assert.equal(receipt.prev, null);
  assert.equal(receipt.anchor, null);
  assert.equal(receipt.countersig, null);
  assert.match(receipt.sub_commit, /^sha256:[0-9a-f]{64}$/);
  assert.match(receipt.field_root, /^sha256:[0-9a-f]{64}$/);
  assert.equal(verifyReceiptSignature(receipt), true);
});

test("mintModification chains via prev to a prior receipt", () => {
  const key = signingKey();
  const consent = mintConsent({
    issuerDid: "did:web:bank.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "alice" },
      purposes: [{ value: "marketing" }],
      policy_hash: { value: "policy-v3" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
  });

  const mod = mintModification({
    prior: consent,
    signingKey: key,
    fields: {
      sub_commit: { value: "alice" },
      purposes: [{ value: "marketing" }, { value: "analytics" }],
      policy_hash: { value: "policy-v4" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-06-01T10:00:00Z",
  });

  assert.equal(mod.kind, "ar.modification.v1");
  assert.equal(mod.prev, hashReceipt(consent));
  assert.equal(verifyReceiptSignature(mod), true);

  const state = resolveChainState([consent, mod]);
  assert.equal(state.status, "modified");
});

test("mintWithdrawal chains and resolves to withdrawn state", () => {
  const key = signingKey();
  const consent = mintConsent({
    issuerDid: "did:web:bank.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "alice" },
      purposes: [{ value: "marketing" }],
      policy_hash: { value: "policy-v3" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
  });

  const wdr = mintWithdrawal({
    prior: consent,
    signingKey: key,
    granted_at: "2026-07-01T10:00:00Z",
  });

  assert.equal(wdr.kind, "ar.withdrawal.v1");
  assert.equal(wdr.prev, hashReceipt(consent));
  assert.equal(verifyReceiptSignature(wdr), true);

  const state = resolveChainState([consent, wdr]);
  assert.equal(state.status, "withdrawn");
});

test("issuer-kit also exposes salts via mintConsent return tuple", () => {
  const key = signingKey();
  const result = mintConsent({
    issuerDid: "did:web:bank.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "alice" },
      purposes: [{ value: "marketing" }],
      policy_hash: { value: "policy-v3" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
    returnSalts: true,
  });
  assert.ok(result.salts);
  assert.equal(typeof result.salts!.sub_commit, "string");
  assert.equal(result.salts!.purposes.length, 1);
});
