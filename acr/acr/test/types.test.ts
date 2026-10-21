import { test } from "node:test";
import assert from "node:assert/strict";
import type { ACRReceipt, AcrKind, AcrProfile } from "../src/types.ts";

test("AcrKind is one of the three allowed values", () => {
  const consent: AcrKind = "ar.consent.v1";
  const modification: AcrKind = "ar.modification.v1";
  const withdrawal: AcrKind = "ar.withdrawal.v1";
  assert.equal(consent, "ar.consent.v1");
  assert.equal(modification, "ar.modification.v1");
  assert.equal(withdrawal, "ar.withdrawal.v1");
});

test("ACRReceipt shape compiles with all required fields", () => {
  const r: ACRReceipt = {
    kind: "ar.consent.v1",
    profile: "gdpr.art7",
    iss: "did:web:bank.example",
    iss_key: "ed25519:abc123",
    sub_commit: "sha256:deadbeef",
    purposes: ["sha256:aaa"],
    lawful_basis: "6(1)(a)",
    policy_hash: "sha256:bbb",
    granted_at: "2026-05-15T10:00:00Z",
    prev: null,
    field_root: "sha256:ccc",
    anchor: null,
    sig: "ed25519:sig",
    countersig: null,
    qts_attestation_hash: null,
  };
  assert.equal(r.kind, "ar.consent.v1");
});

test("AcrProfile enumerates the six v1 profiles", () => {
  const profiles: AcrProfile[] = [
    "gdpr.art7",
    "aiact.art14",
    "hipaa.auth",
    "kyc.consent",
    "mifid2.suit",
    "esig.accept",
  ];
  assert.equal(profiles.length, 6);
});
