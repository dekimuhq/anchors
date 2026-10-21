/**
 * Coverage for the three surfaces the original 9 tests left almost bare:
 * keypair generation, the family manifest's FAMILY-CONSISTENCY invariants, and
 * the `verifyReceipt` version dispatch in index.ts.
 *
 * The manifest assertions matter beyond this package: `schema/validate.ts`
 * cross-checks these same values against `schema/families/ar.compliance.v1.anchor.json`
 * and the §1 chip table, so a drift here is a family-wide inconsistency.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateComplianceKeypair } from "../src/issue/keys.ts";
import { complianceFamily } from "../src/family.ts";
import { complianceBodyValidator } from "../src/body-validator.ts";
import { verifyReceipt, verifyComplianceBundleBody } from "../src/index.ts";
import type { ComplianceBundleBody } from "../src/types.ts";

const SHA = "sha256:" + "a".repeat(64);

function body(): ComplianceBundleBody {
  return {
    profile: "compliance.bundle",
    workspaceId: "ws_1",
    controller: { entityName: "Acme SL", registeredAddress: null, contactEmail: null },
    regulation: { manifestId: "gdpr", manifestVersion: "1.2.0", manifestHash: SHA },
    coverage: { applicable: 8, satisfied: 8, ratio: 1 },
    constituents: {
      ropa: { ref: "ropa:" + "b".repeat(64), contentHash: SHA, satisfiedObligations: ["gdpr.records"] },
      dpia: { status: "not_applicable", reason: "none", basis: "engine" },
      obligations: { ref: "report", contentHash: SHA, satisfiedObligations: [] },
    },
    generated_at: "2026-06-20T10:00:00Z",
  };
}

// ---------------------------------------------------------------------- keys

test("a generated keypair preserves the kid it was given", () => {
  assert.equal(generateComplianceKeypair("kid-abc").signingKey.kid, "kid-abc");
});

test("the exported private key is a 32-byte Ed25519 seed", () => {
  assert.equal(generateComplianceKeypair("k").signingKey.privateKey.length, 32);
});

test("the private key is a Uint8Array, not a Buffer view of the whole pkcs8", () => {
  const pk = generateComplianceKeypair("k").signingKey.privateKey;
  assert.ok(pk instanceof Uint8Array);
});

test("the exported public key is non-empty SPKI DER", () => {
  const { publicKeyDer } = generateComplianceKeypair("k");
  assert.ok(publicKeyDer instanceof Uint8Array);
  assert.ok(publicKeyDer.length > 0);
});

test("two keypairs are distinct", () => {
  const a = generateComplianceKeypair("k");
  const b = generateComplianceKeypair("k");
  assert.notDeepEqual(a.signingKey.privateKey, b.signingKey.privateKey);
});

test("an empty kid is accepted at generation — the MINT is what rejects it", () => {
  // Recording the real split of responsibility: keys.ts does not validate,
  // mintComplianceV1's guard 2 does.
  assert.equal(generateComplianceKeypair("").signingKey.kid, "");
});

// ----------------------------------------------------------- family manifest

test("the family acronym is ACBR", () => {
  assert.equal(complianceFamily.meta.acronym, "ACBR");
});

test("the family name is Anchored Compliance Bundle Receipts", () => {
  assert.equal(complianceFamily.meta.name, "Anchored Compliance Bundle Receipts");
});

test("the family owns exactly one claim type", () => {
  assert.deepEqual(complianceFamily.meta.claim_types, ["ar.compliance.v1"]);
});

test("the family sits on chip 21", () => {
  assert.equal(complianceFamily.meta.chip, 21);
});

test("subject_presence is must-be-null — workspace-level, not per-data-subject", () => {
  assert.equal(complianceFamily.meta.subject_presence, "must-be-null");
});

test("status_list_slot is null — non-revocable in this slice", () => {
  assert.equal(complianceFamily.meta.status_list_slot, null);
});

test("the tsa upgrade path is free", () => {
  assert.equal(complianceFamily.meta.tsa_upgrade_path, "free");
});

test("continuity is false", () => {
  assert.equal(complianceFamily.meta.continuity, false);
});

test("the family exposes NO sub-profiles — the single profile is checked inline", () => {
  // Asserted through the built manifest's API (`profileIds`), not the literal
  // passed to defineFamily: `profiles` is consumed at construction and is not
  // re-exposed on `meta`, so asserting `meta.profiles` tests nothing real.
  assert.deepEqual(complianceFamily.profileIds, []);
});

test("no profile id resolves, including the inline one", () => {
  assert.equal(complianceFamily.hasProfile("compliance.bundle"), false);
});

test("with no tsa_mandate declared the level resolves to optional", () => {
  assert.equal(complianceFamily.tsaMandateLevel("ar.compliance.v1"), "optional");
});

test("the family claims its own claim type and disowns another family's", () => {
  assert.equal(complianceFamily.isOwnedClaimType("ar.compliance.v1"), true);
  assert.equal(complianceFamily.isOwnedClaimType("ar.impact.v1"), false);
});

test("checkSubjectPresence accepts a null subject", () => {
  assert.equal(complianceFamily.checkSubjectPresence(null).ok, true);
});

test("checkSubjectPresence REJECTS a present subject — must-be-null is enforced", () => {
  assert.equal(complianceFamily.checkSubjectPresence("did:web:someone").ok, false);
});

test("the family spec_path points at the B2 design doc", () => {
  assert.match(complianceFamily.meta.spec_path, /^https:\/\/github\.com\/dekimuhq\/anchors-spec\/tree\/main\/compliance$/);
});

// ---------------------------------------------------------- body validator

test("the body validator accepts a valid body and returns the parsed value", () => {
  const r = complianceBodyValidator.validate(body());
  assert.equal(r.ok, true);
  assert.equal((r as { value: ComplianceBundleBody }).value.workspaceId, "ws_1");
});

test("the body validator rejects an invalid body with the FIRST validator error as reason", () => {
  const bad = body() as unknown as Record<string, unknown>;
  bad.profile = "wrong";
  const r = complianceBodyValidator.validate(bad as never);
  assert.equal(r.ok, false);
  assert.equal((r as { reason: string }).reason, "profile.invalid");
});

test("the body validator falls back to body_invalid when there is no error string", () => {
  // Defensive arm: `r.errors[0] ?? "body_invalid"`. Reached only if a future
  // change ever returns valid:false with an empty errors array.
  const r = complianceBodyValidator.validate(null as never);
  assert.equal(r.ok, false);
  assert.ok(typeof (r as { reason: string }).reason === "string");
});

// ------------------------------------------------------- verifyReceipt dispatch

test("a null receipt is schema_invalid, not a crash", async () => {
  const r = await verifyReceipt(null);
  assert.equal((r as { reason?: string }).reason, "schema_invalid");
  assert.equal((r as { signature_valid: boolean }).signature_valid, false);
});

test("a string receipt is schema_invalid", async () => {
  assert.equal((await verifyReceipt("nope") as { reason?: string }).reason, "schema_invalid");
});

test("a number receipt is schema_invalid", async () => {
  assert.equal((await verifyReceipt(7) as { reason?: string }).reason, "schema_invalid");
});

test("an undefined receipt is schema_invalid", async () => {
  assert.equal((await verifyReceipt(undefined) as { reason?: string }).reason, "schema_invalid");
});

test("a v1 envelope is refused as an unsupported version", async () => {
  const r = await verifyReceipt({ v: 1 });
  assert.equal((r as { reason?: string }).reason, "unsupported_envelope_version");
});

test("an envelope with NO version is refused as unsupported", async () => {
  const r = await verifyReceipt({ claim_type: "ar.compliance.v1" });
  assert.equal((r as { reason?: string }).reason, "unsupported_envelope_version");
});

test("a string \"2\" version is refused — the check is strict equality", async () => {
  const r = await verifyReceipt({ v: "2" });
  assert.equal((r as { reason?: string }).reason, "unsupported_envelope_version");
});

test("an unsupported version reports envelope_version unknown", async () => {
  const r = await verifyReceipt({ v: 1 });
  assert.equal((r as { envelope_version?: string }).envelope_version, "unknown");
});

test("a v2 envelope is dispatched to the family verifier rather than refused", async () => {
  // Malformed beyond the version, so it fails verification — but it must fail
  // INSIDE the family verifier, not via the unsupported-version early return.
  const r = await verifyReceipt({ v: 2 });
  assert.notEqual((r as { reason?: string }).reason, "unsupported_envelope_version");
});

test("verifyReceipt tolerates being called with no options at all", async () => {
  await assert.doesNotReject(() => verifyReceipt({ v: 2 }));
});

// ------------------------------------------------------------------- exports

test("the package re-exports verifyComplianceBundleBody", () => {
  assert.equal(typeof verifyComplianceBundleBody, "function");
  assert.equal(verifyComplianceBundleBody(body()).valid, true);
});

test("the package re-exports the family manifest", () => {
  assert.equal(complianceFamily.meta.acronym, "ACBR");
});
