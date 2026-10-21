import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "../src/issue/keys.ts";
import { mintConsent } from "../src/issue/mint.ts";
import { buildDisclosureProof } from "../src/issue/disclose.ts";
import { verifyDisclosureProof } from "../src/index.ts";

test("buildDisclosureProof produces a verifiable proof for sub_commit", () => {
  const key = generateKeypair("k1");
  const receipt = mintConsent({
    issuerDid: "did:web:bank.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "alice@example.com" },
      purposes: [{ value: "marketing" }, { value: "analytics" }],
      policy_hash: { value: "policy-v3" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
    returnSalts: true,
  });

  const proof = buildDisclosureProof({
    receipt,
    salts: receipt.salts!,
    field: "sub_commit",
    value: "alice@example.com",
  });

  assert.equal(verifyDisclosureProof(proof, receipt.field_root), true);
});

test("buildDisclosureProof for a specific purpose entry", () => {
  const key = generateKeypair("k1");
  const receipt = mintConsent({
    issuerDid: "did:web:bank.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "alice" },
      purposes: [{ value: "marketing" }, { value: "analytics" }],
      policy_hash: { value: "policy-v3" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
    returnSalts: true,
  });

  const proof = buildDisclosureProof({
    receipt,
    salts: receipt.salts!,
    field: "purposes[1]",
    value: "analytics",
  });

  assert.equal(verifyDisclosureProof(proof, receipt.field_root), true);
});

test("buildDisclosureProof for policy_hash", () => {
  const key = generateKeypair("k1");
  const receipt = mintConsent({
    issuerDid: "did:web:bank.example",
    signingKey: key,
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "alice" },
      purposes: [{ value: "marketing" }],
      policy_hash: { value: "policy-v3-text" },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-15T10:00:00Z",
    returnSalts: true,
  });

  const proof = buildDisclosureProof({
    receipt,
    salts: receipt.salts!,
    field: "policy_hash",
    value: "policy-v3-text",
  });

  assert.equal(verifyDisclosureProof(proof, receipt.field_root), true);
});

test("buildDisclosureProof throws on field/value mismatch", () => {
  const key = generateKeypair("k1");
  const receipt = mintConsent({
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

  assert.throws(
    () =>
      buildDisclosureProof({
        receipt,
        salts: receipt.salts!,
        field: "sub_commit",
        value: "bob",
      }),
    /commitment mismatch/,
  );
});

test("buildDisclosureProof rejects unsupported field name", () => {
  const key = generateKeypair("k1");
  const receipt = mintConsent({
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

  assert.throws(
    () =>
      buildDisclosureProof({
        receipt,
        salts: receipt.salts!,
        field: "lawful_basis",
        value: "6(1)(a)",
      }),
    /unsupported field/,
  );
});

test("buildDisclosureProof rejects out-of-range purposes index", () => {
  const key = generateKeypair("k1");
  const receipt = mintConsent({
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

  assert.throws(
    () =>
      buildDisclosureProof({
        receipt,
        salts: receipt.salts!,
        field: "purposes[5]",
        value: "marketing",
      }),
    /bad purposes index/,
  );
});
