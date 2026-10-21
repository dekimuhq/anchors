/**
 * Cross-package end-to-end lifecycle tests for the Anchored Receipts family.
 *
 * Covers:
 *  1. ACR consent → modification → withdrawal lifecycle (Task 15, plan-verbatim)
 *  2. ACR selective-disclosure proof (Task 15, plan-verbatim)
 *  3. @dekimuhq/anchors meta-package contract (surgical + namespaced imports)
 *  4. APR mint → verifyClaim roundtrip
 *  5. ARR mintErasure → verifySingleReceipt roundtrip + gdpr.art17 profile
 */

import { test } from "node:test";
import assert from "node:assert/strict";

// Direct ACR imports (plan-verbatim).
import {
  generateKeypair,
  mintConsent,
  mintModification,
  mintWithdrawal,
  buildDisclosureProof,
} from "@dekimuhq/acr/issue";
import {
  verifyReceiptSignature,
  resolveChainState,
  verifyDisclosureProof,
  hashReceipt,
} from "@dekimuhq/acr";
import { validateGdprArt7 } from "@dekimuhq/acr-profiles";

// Surgical meta imports (locks `@dekimuhq/anchors/<family>` subpath contract).
import {
  mintConsent as metaMintConsent,
  generateKeypair as metaGenerateKeypair,
} from "@dekimuhq/anchors/acr";
import { mint as metaApMint, generateKeypair as metaApGenerateKeypair } from "@dekimuhq/anchors/apr";

// Namespaced meta import (locks `@dekimuhq/anchors` index contract).
import * as anchors from "@dekimuhq/anchors";

// APR direct imports.
import { mint as aprMint, generateKeypair as aprGenerateKeypair } from "@dekimuhq/apr/issue";
import { verifyClaim, type ClaimKeyResolver, type APRBody } from "@dekimuhq/apr";

// ARR direct imports.
import {
  generateIssuerKey,
  encodePublicKey,
  mintErasure,
} from "@dekimuhq/arr/issue";
import { verifySingleReceipt } from "@dekimuhq/arr";
import { validateGdprArt17 } from "@dekimuhq/arr-profiles";

// ──────────────────────────────────────────────────────────────────────────────
// 1. ACR full lifecycle (plan-verbatim).
// ──────────────────────────────────────────────────────────────────────────────

test("ACR: full consent → modification → withdrawal lifecycle is verifiable", () => {
  const key = generateKeypair("bank-example-key-2026");

  // No `returnSalts` in the lifecycle test — `MintResult.salts` is an extra field
  // outside the signed canonical view, so passing a salts-bearing receipt to
  // `verifyReceiptSignature` would canonicalize a different shape than was signed
  // and fail. Salts are only needed for selective disclosure (see next test).
  const consent = mintConsent({
    issuerDid: "did:web:bank.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "alice@example.com" },
      purposes: [{ value: "marketing-emails" }],
      policy_hash: { value: "policy-2026-Q2-v3" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
  });

  assert.equal(verifyReceiptSignature(consent), true, "consent signature verifies");
  assert.equal(validateGdprArt7(consent).valid, true, "consent passes gdpr.art7 profile");

  const mod = mintModification({
    prior: consent,
    signingKey: key,
    fields: {
      sub_commit: { value: "alice@example.com" },
      purposes: [{ value: "marketing-emails" }, { value: "analytics" }],
      policy_hash: { value: "policy-2026-Q2-v3" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-06-01T10:00:00Z",
  });

  assert.equal(verifyReceiptSignature(mod), true, "modification signature verifies");
  assert.equal(mod.prev, hashReceipt(consent), "modification chains to consent");

  const wdr = mintWithdrawal({
    prior: mod,
    signingKey: key,
    granted_at: "2026-07-01T10:00:00Z",
  });

  assert.equal(verifyReceiptSignature(wdr), true, "withdrawal signature verifies");
  assert.equal(wdr.prev, hashReceipt(mod), "withdrawal chains to modification");

  const state = resolveChainState([consent, mod, wdr]);
  assert.equal(state.status, "withdrawn");
  assert.equal(state.terminal_kind, "ar.withdrawal.v1");
  assert.equal(state.terminal_granted_at, "2026-07-01T10:00:00Z");
});

// ──────────────────────────────────────────────────────────────────────────────
// 2. ACR selective disclosure (plan-verbatim).
// ──────────────────────────────────────────────────────────────────────────────

test("ACR: selective disclosure proves policy_hash without leaking subject identity", () => {
  const key = generateKeypair("k");
  const consent = mintConsent({
    issuerDid: "did:web:bank.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "alice@example.com" },
      purposes: [{ value: "marketing" }],
      policy_hash: { value: "policy-v3" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
    returnSalts: true,
  });

  const proof = buildDisclosureProof({
    receipt: consent,
    salts: consent.salts!,
    field: "policy_hash",
    value: "policy-v3",
  });

  assert.equal(verifyDisclosureProof(proof, consent.field_root), true);
  assert.equal(proof.disclosure.field, "policy_hash");
  assert.equal(proof.disclosure.value, "policy-v3");
});

// ──────────────────────────────────────────────────────────────────────────────
// 3. @dekimuhq/anchors meta-package contract.
//    Locks both subpath (`/acr`, `/apr`) and namespaced (`*`) imports.
// ──────────────────────────────────────────────────────────────────────────────

test("anchors meta: surgical import (`@dekimuhq/anchors/acr`) mints + verifies", () => {
  const key = metaGenerateKeypair("meta-acr-key");
  const consent = metaMintConsent({
    issuerDid: "did:web:meta.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "bob@example.com" },
      purposes: [{ value: "marketing" }],
      policy_hash: { value: "policy-v1" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
  });

  // Verify via the direct verifier package — the meta surgical import must produce
  // a receipt that round-trips through the canonical verifier.
  assert.equal(verifyReceiptSignature(consent), true);
});

test("anchors meta: namespaced import (`anchors.acr` / `anchors.apr` / `anchors.arr` / `anchors.arrProfiles`)", () => {
  // Exhaustive namespace check: all four families are reachable and at least one
  // canonical entry point per family is callable from the namespaced index.
  assert.equal(typeof anchors.acr.mintConsent, "function");
  assert.equal(typeof anchors.acr.verifyReceiptSignature, "function");
  assert.equal(typeof anchors.apr.mint, "function");
  assert.equal(typeof anchors.apr.verify, "function");
  assert.equal(typeof anchors.arr.verifySingleReceipt, "function");
  assert.equal(typeof anchors.arrProfiles.validateGdprArt17, "function");

  // End-to-end smoke through the namespaced API: mint an ACR consent and verify
  // its signature — both calls via `anchors.acr.*`.
  const key = anchors.acr.generateKeypair("anchors-ns-key");
  const consent = anchors.acr.mintConsent({
    issuerDid: "did:web:ns.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "carol@example.com" },
      purposes: [{ value: "marketing" }],
      policy_hash: { value: "policy-ns-v1" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
  });
  assert.equal(anchors.acr.verifyReceiptSignature(consent), true);
});

// ──────────────────────────────────────────────────────────────────────────────
// 4. APR mint → verifyClaim roundtrip (direct + via meta).
// ──────────────────────────────────────────────────────────────────────────────

const aprBody: APRBody = {
  artifact: {
    type: "miniterms.document",
    id: "art-e2e-001",
    hash: "0".repeat(64),
    hashAlgorithm: "sha256",
  },
  agent: { kind: "template" },
  authorization: { principalId: "principal-e2e" },
  startedAt: 1000,
  completedAt: 1001,
  disclosure: "public_minimal",
  qts_attestation_hash: null,
};

test("APR: mint → verifyClaim roundtrip via direct package", () => {
  const kp = aprGenerateKeypair("apr-e2e-2026");
  const claim = aprMint({
    issuer: "test-issuer",
    subject: "art-e2e-001",
    body: aprBody,
    signingKey: { kid: kp.kid, privateKey: kp.privateKey },
    now: () => 1000,
    newId: () => "01J0E2E00000000000000A0001",
  });
  assert.equal(claim.kind, "ar.provenance.v1");

  const resolver: ClaimKeyResolver = (k) =>
    k === kp.kid
      ? { kid: kp.kid, publicKey: kp.publicKey, issuer: "test-issuer" }
      : undefined;
  const result = verifyClaim(claim, resolver, 1500);
  assert.equal(result.ok, true);
});

test("APR: mint via `@dekimuhq/anchors/apr` is verified by the same verifier", () => {
  const kp = metaApGenerateKeypair("apr-meta-2026");
  const claim = metaApMint({
    issuer: "meta-issuer",
    subject: "art-meta-001",
    body: aprBody,
    signingKey: { kid: kp.kid, privateKey: kp.privateKey },
    now: () => 2000,
    newId: () => "01J0E2E00000000000000A0002",
  });

  const resolver: ClaimKeyResolver = (k) =>
    k === kp.kid
      ? { kid: kp.kid, publicKey: kp.publicKey, issuer: "meta-issuer" }
      : undefined;
  const result = verifyClaim(claim, resolver, 2500);
  assert.equal(result.ok, true);
});

// ──────────────────────────────────────────────────────────────────────────────
// 5. ARR mintErasure → verifySingleReceipt + gdpr.art17 profile validator.
// ──────────────────────────────────────────────────────────────────────────────

test("ARR: mintErasure → verifySingleReceipt roundtrip + gdpr.art17 passes", () => {
  const kp = generateIssuerKey();
  const issKey = encodePublicKey(kp.publicKey);

  const receipt = mintErasure({
    iss: "did:web:bank.example",
    iss_key: issKey,
    privateKey: kp.privateKey,
    profile: "gdpr.art17",
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
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: "sha256:" + "cd".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
    prev: null,
    extraFields: {
      subject_data_categories: ["sha256:" + "01".repeat(32)],
      controller_contact_hash: "sha256:" + "02".repeat(32),
    },
  });

  assert.equal(receipt.kind, "ar.erasure.v1");

  // Signature + structural checks: anchor inclusion time is after granted_at.
  const verifyResult = verifySingleReceipt(receipt, {
    anchorInclusionTime: "2026-05-16T09:20:00Z",
  });
  assert.deepEqual(verifyResult.errors, []);
  assert.equal(verifyResult.valid, true);

  // Profile validator: gdpr.art17 fulfilment requires erasure/anonymization kind +
  // subject_data_categories + controller_contact_hash. All three present.
  const profileResult = validateGdprArt17(receipt);
  assert.deepEqual(profileResult.errors, []);
});
