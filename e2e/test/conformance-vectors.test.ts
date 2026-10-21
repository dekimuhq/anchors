/**
 * Conformance vector validation — reads JSON vectors from anchors-spec/conformance/
 * and verifies each against the appropriate family verifier.
 *
 * Valid vectors MUST verify with signature_valid: true.
 * Invalid vectors MUST fail with the expected reason category.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  verifyEnvelopeSignature,
  isKnownClaimType,
  checkIatMs,
  checkPredicate,
  base64UrlDecode,
} from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import { verifyReceipt as verifyApr } from "@dekimuhq/apr";
import { verifyReceipt as verifyAcr } from "@dekimuhq/acr";
import { verifyReceipt as verifyArr } from "@dekimuhq/arr";

// ── Helpers ─────────────────────────────────────────────────────────────────

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const CONFORMANCE_ROOT = path.resolve(
  import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname),
  "../../../anchors-spec/conformance",
);

interface ValidVector {
  description: string;
  receipt: Record<string, unknown>;
  issuer_public_key: string;
  expected_result: { signature: string; claim_type: string };
}

interface InvalidVector {
  description: string;
  receipt: Record<string, unknown>;
  issuer_public_key: string;
  expected_error: string;
}

function loadVector<T>(relPath: string): T {
  const abs = path.join(CONFORMANCE_ROOT, relPath);
  return JSON.parse(fs.readFileSync(abs, "utf8")) as T;
}

function derFromRawPublicKey(b64url: string): Uint8Array {
  const raw = base64UrlDecode(b64url);
  return new Uint8Array(Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(raw)]));
}

/** Map claim_type to the family verifier's verifyReceipt function. */
const APR_CLAIM_TYPES = new Set(["ar.provenance.v1"]);
const ACR_CLAIM_TYPES = new Set(["ar.consent.v1", "ar.modification.v1", "ar.withdrawal.v1"]);
const ARR_CLAIM_TYPES = new Set([
  "ar.erasure.v1", "ar.expiry.v1", "ar.hold.v1",
  "ar.anonymization.v1", "ar.archive.v1", "ar.batch.v1",
]);

function familyVerifier(claimType: string) {
  if (APR_CLAIM_TYPES.has(claimType)) return verifyApr;
  if (ACR_CLAIM_TYPES.has(claimType)) return verifyAcr;
  if (ARR_CLAIM_TYPES.has(claimType)) return verifyArr;
  return null;
}

// ── Valid vector tests ──────────────────────────────────────────────────────

const VALID_FILES = [
  "valid/apr-provenance-v1.json",
  "valid/acr-consent-v1.json",
  "valid/arr-erasure-v1.json",
];

for (const file of VALID_FILES) {
  test(`conformance valid: ${file}`, async () => {
    const v = loadVector<ValidVector>(file);
    const derKey = derFromRawPublicKey(v.issuer_public_key);
    const envelope = v.receipt as unknown as Envelope;

    // 1. Low-level envelope signature check.
    const sigOk = verifyEnvelopeSignature(envelope, derKey);
    assert.strictEqual(sigOk, true, `Envelope signature must verify for ${file}`);

    // 2. claim_type must be known.
    assert.strictEqual(
      isKnownClaimType(envelope.claim_type),
      true,
      `claim_type '${envelope.claim_type}' must be known`,
    );

    // 3. iat_ms check (v1.2).
    const iatR = checkIatMs(envelope);
    assert.strictEqual(iatR.ok, true, `iat_ms check must pass for ${file}`);

    // 4. predicate check (v1.2).
    const predR = checkPredicate(envelope);
    assert.strictEqual(predR.ok, true, `predicate check must pass for ${file}`);

    // 5. Full family verifier round-trip.
    const verify = familyVerifier(envelope.claim_type);
    assert.ok(verify, `No family verifier found for ${envelope.claim_type}`);
    const result = await verify(v.receipt, {
      resolveKey: () => derKey,
    });
    assert.strictEqual(
      result.signature_valid,
      true,
      `Family verifier must return signature_valid=true for ${file}, got reason=${(result as { reason?: string }).reason}`,
    );
    assert.strictEqual(
      v.expected_result.claim_type,
      envelope.claim_type,
      "expected_result.claim_type must match receipt claim_type",
    );
  });
}

// ── Invalid vector tests ────────────────────────────────────────────────────

test("conformance invalid: sig-invalid.json", async () => {
  const v = loadVector<InvalidVector>("invalid/sig-invalid.json");
  const derKey = derFromRawPublicKey(v.issuer_public_key);
  const envelope = v.receipt as unknown as Envelope;

  // Low-level: signature must NOT verify.
  const sigOk = verifyEnvelopeSignature(envelope, derKey);
  assert.strictEqual(sigOk, false, "Tampered signature must not verify");

  // Family verifier must also reject.
  const verify = familyVerifier(envelope.claim_type);
  assert.ok(verify, "Must have a family verifier for the claim_type");
  const result = await verify(v.receipt, { resolveKey: () => derKey });
  assert.strictEqual(result.signature_valid, false, "Family verifier must reject tampered sig");
  assert.strictEqual(
    (result as { reason?: string }).reason,
    "signature_invalid",
    "Reason must be signature_invalid",
  );
});

test("conformance invalid: claim-type-unknown.json", async () => {
  const v = loadVector<InvalidVector>("invalid/claim-type-unknown.json");
  const derKey = derFromRawPublicKey(v.issuer_public_key);
  const envelope = v.receipt as unknown as Envelope;

  // claim_type must NOT be known.
  assert.strictEqual(
    isKnownClaimType(envelope.claim_type),
    false,
    "ar.unknown.v1 must not be a known claim type",
  );

  // Every family verifier rejects with wrong_protocol or schema_invalid:claim_type.
  // Use APR verifier as representative (it hits the global claim_type gate first).
  const result = await verifyApr(v.receipt, { resolveKey: () => derKey });
  assert.strictEqual(result.signature_valid, false, "Verifier must reject unknown claim_type");
  const reason = (result as { reason?: string }).reason;
  assert.ok(
    reason === "schema_invalid:claim_type" || reason === "wrong_protocol",
    `Expected schema_invalid:claim_type or wrong_protocol, got ${reason}`,
  );
});

test("conformance invalid: iat-ms-mismatch.json", async () => {
  const v = loadVector<InvalidVector>("invalid/iat-ms-mismatch.json");
  const derKey = derFromRawPublicKey(v.issuer_public_key);
  const envelope = v.receipt as unknown as Envelope;

  // checkIatMs must fail.
  const iatR = checkIatMs(envelope);
  assert.strictEqual(iatR.ok, false, "iat_ms check must fail for mismatched value");
  assert.strictEqual(
    (iatR as { reason: string }).reason,
    "iat_ms_mismatch",
    "Reason must be iat_ms_mismatch",
  );

  // Family verifier must also reject.
  const result = await verifyAcr(v.receipt, { resolveKey: () => derKey });
  assert.strictEqual(result.signature_valid, false, "Verifier must reject iat_ms mismatch");
  assert.strictEqual(
    (result as { reason?: string }).reason,
    "iat_ms_mismatch",
    "Reason must be iat_ms_mismatch",
  );
});

test("conformance invalid: predicate-operator-not-allowed.json", async () => {
  const v = loadVector<InvalidVector>("invalid/predicate-operator-not-allowed.json");
  const derKey = derFromRawPublicKey(v.issuer_public_key);
  const envelope = v.receipt as unknown as Envelope;

  // checkPredicate must fail.
  const predR = checkPredicate(envelope);
  assert.strictEqual(predR.ok, false, "Predicate check must fail for forbidden operator");
  assert.strictEqual(
    (predR as { reason: string }).reason,
    "predicate_operator_not_allowed",
    "Reason must be predicate_operator_not_allowed",
  );

  // Family verifier must also reject.
  const result = await verifyAcr(v.receipt, { resolveKey: () => derKey });
  assert.strictEqual(result.signature_valid, false, "Verifier must reject forbidden predicate op");
  assert.strictEqual(
    (result as { reason?: string }).reason,
    "predicate_operator_not_allowed",
    "Reason must be predicate_operator_not_allowed",
  );
});
