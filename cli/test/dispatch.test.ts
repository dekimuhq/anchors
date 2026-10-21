/**
 * Claim-type dispatch + verifyAnchor round-trip tests.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  verifyAnchor,
  supportedClaimTypes,
  ALL_FAMILIES,
} from "../src/dispatch.ts";
import { selfCertifyingResolveKey } from "../src/resolve-key.ts";
import { mintAsrReceipt } from "./_helpers.ts";

const opts = { resolveKey: selfCertifyingResolveKey };

test("ALL_FAMILIES: 14 family manifests registered", () => {
  assert.equal(ALL_FAMILIES.length, 14);
});

test("supportedClaimTypes: includes every family's core discriminator", () => {
  const ct = new Set(supportedClaimTypes());
  for (const expected of [
    "ar.provenance.v1",
    "ar.consent.v1",
    "ar.lineage.v1",
    "ar.notice.v1",
    "ar.subject_rights.v1",
    "ar.breach.v1",
    "ar.impact.v1",
    "ar.tokenization.v1",
    "ar.attestation.v1",
    "ar.delegation.v1",
    "ar.evaluation.v1",
    "ar.transfer.v1",
    "ar.purpose.v1",
  ]) {
    assert.ok(ct.has(expected), `missing ${expected}`);
  }
});

test("supportedClaimTypes: sorted, no duplicates", () => {
  const list = supportedClaimTypes();
  assert.deepEqual(list, [...list].sort());
  assert.equal(list.length, new Set(list).size);
});

test("verifyAnchor: missing claim_type -> dispatch reason", async () => {
  const out = await verifyAnchor({ foo: 1 }, opts);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "missing_claim_type");
  assert.equal(out.result, null);
});

test("verifyAnchor: unknown claim_type -> dispatch reason", async () => {
  const out = await verifyAnchor({ claim_type: "ar.nonsense.v9" }, opts);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "unknown_claim_type");
  assert.equal(out.claim_type, "ar.nonsense.v9");
  assert.equal(out.family, null);
});

test("verifyAnchor: non-object receipt -> missing_claim_type", async () => {
  assert.equal((await verifyAnchor(null, opts)).reason, "missing_claim_type");
  assert.equal((await verifyAnchor("string", opts)).reason, "missing_claim_type");
});

test("verifyAnchor: valid minted ASR receipt verifies (self-certifying)", async () => {
  const receipt = await mintAsrReceipt();
  const out = await verifyAnchor(receipt, opts);
  assert.equal(out.ok, true, `unexpected: ${out.result?.reason}`);
  assert.equal(out.family, "ASR");
  assert.equal(out.claim_type, "ar.subject_rights.v1");
  assert.equal(out.result?.signature_valid, true);
});

test("verifyAnchor: tampered receipt fails signature", async () => {
  const receipt = await mintAsrReceipt();
  const tampered = { ...receipt, subject: "sha256:" + "f".repeat(64) };
  const out = await verifyAnchor(tampered, opts);
  assert.equal(out.ok, false);
  assert.equal(out.family, "ASR");
});

test("verifyAnchor: unresolvable issuer key fails (issuer unknown)", async () => {
  const receipt = await mintAsrReceipt();
  // Strip iss_key so the self-certifying resolver returns null.
  const noKey = { ...receipt, iss_key: undefined };
  const out = await verifyAnchor(noKey, { resolveKey: selfCertifyingResolveKey });
  assert.equal(out.ok, false);
});
