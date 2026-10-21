import { test } from "node:test";
import assert from "node:assert/strict";
import { validateGdprArt7 } from "../src/gdpr-art7.ts";
import type { ACRReceipt } from "@dekimuhq/acr-profiles/body-types";

function baseReceipt(overrides: Partial<ACRReceipt> = {}): ACRReceipt {
  return {
    kind: "ar.consent.v1",
    profile: "gdpr.art7",
    iss: "did:web:bank.example",
    iss_key: "ed25519:x",
    sub_commit: "sha256:" + "a".repeat(64),
    purposes: ["sha256:" + "b".repeat(64)],
    lawful_basis: "6(1)(a)",
    policy_hash: "sha256:" + "c".repeat(64),
    granted_at: "2026-05-15T10:00:00Z",
    prev: null,
    field_root: "sha256:" + "d".repeat(64),
    anchor: null,
    sig: "ed25519:sig",
    countersig: null,
    qts_attestation_hash: null,
    ...overrides,
  };
}

test("validateGdprArt7 accepts each allowed lawful basis", () => {
  for (const lb of ["6(1)(a)", "6(1)(b)", "6(1)(c)", "6(1)(d)", "6(1)(e)", "6(1)(f)"]) {
    const r = baseReceipt({ lawful_basis: lb });
    assert.equal(validateGdprArt7(r).valid, true, `should accept ${lb}`);
  }
});

test("validateGdprArt7 rejects an invalid lawful basis", () => {
  const r = baseReceipt({ lawful_basis: "9(2)(a)" });
  const result = validateGdprArt7(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("lawful_basis")));
});

test("validateGdprArt7 rejects wrong profile", () => {
  const r = baseReceipt({ profile: "aiact.art14" });
  const result = validateGdprArt7(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("profile")));
});

test("validateGdprArt7 requires at least one purpose", () => {
  const r = baseReceipt({ purposes: [] });
  const result = validateGdprArt7(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("purposes")));
});

test("validateGdprArt7 requires granted_at to be RFC 3339 UTC", () => {
  const r = baseReceipt({ granted_at: "May 15, 2026" });
  const result = validateGdprArt7(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("granted_at")));
});

test("validateGdprArt7 rejects malformed expires_at when present", () => {
  const r = baseReceipt({ expires_at: "next Tuesday" });
  const result = validateGdprArt7(r);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("expires_at")));
});

test("validateGdprArt7 accepts a well-formed expires_at", () => {
  const r = baseReceipt({ expires_at: "2027-05-15T10:00:00Z" });
  assert.equal(validateGdprArt7(r).valid, true);
});
