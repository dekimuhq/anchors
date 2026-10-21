// Body-aware entry point: verifyReceiptNonRevocation binds the stapled proof to
// the receipt body's executed_at, credential_id, and request_id_commit. PURE —
// the caller resolves the issuer public key and passes it in. Fail-closed when
// the proof is absent or any binding/signature check fails.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "@dekimuhq/anchors-envelope";
import {
  buildNonRevocationProof,
  verifyReceiptNonRevocation,
} from "../src/non-revocation.ts";
import type { AActRBody } from "../src/body.ts";

const H = (c: string): string => `sha256:${c.repeat(64)}`;
const REQUEST_ID_COMMIT = H("c");

function issuerKey() {
  const kp = generateKeypair("a4-receipt-test");
  return { seed: kp.privateKey, pub: kp.publicKey };
}

/** Minimal mandate-bound AActR body carrying a built proof bound to it. */
function bodyWithProof(seed: Uint8Array, overrides: Partial<AActRBody> = {}): AActRBody {
  const credentialId = "adr-grant-123";
  const proof = buildNonRevocationProof(
    {
      credentialId,
      asOf: "2026-06-30T10:00:01Z",
      statusListRef: "https://verify.dekimu.com/mandate-status/2026-06",
      receiptCommit: REQUEST_ID_COMMIT,
    },
    seed,
  );
  return {
    profile: "hub.automation",
    verb: "invoiceup.remind",
    rule_id: "r1",
    recipe_id: "auto-remind-overdue",
    outcome: "executed",
    executed_at: "2026-06-30T10:00:00Z",
    decision_commit: H("a"),
    params_commit: H("b"),
    request_id_commit: REQUEST_ID_COMMIT,
    credential_id: credentialId,
    non_revocation_proof: proof,
    ...overrides,
  };
}

test("valid: proof bound to the body verifies", () => {
  const { seed, pub } = issuerKey();
  const body = bodyWithProof(seed);
  const r = verifyReceiptNonRevocation(body, pub);
  assert.equal(r.valid, true, r.reason);
});

test("invalid: body.request_id_commit differs from the proof's receipt_commit", () => {
  const { seed, pub } = issuerKey();
  // Proof was signed over REQUEST_ID_COMMIT; the body now claims a different one.
  const body = bodyWithProof(seed, { request_id_commit: H("d") });
  const r = verifyReceiptNonRevocation(body, pub);
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /receipt_commit/);
});

test("invalid: body has no non_revocation_proof", () => {
  const { seed, pub } = issuerKey();
  const body = bodyWithProof(seed);
  const { non_revocation_proof, ...rest } = body;
  const r = verifyReceiptNonRevocation(rest as AActRBody, pub);
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /no non_revocation_proof/);
});

test("invalid: body has no credential_id to bind to", () => {
  const { seed, pub } = issuerKey();
  const body = bodyWithProof(seed);
  const { credential_id, ...rest } = body;
  const r = verifyReceiptNonRevocation(rest as AActRBody, pub);
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /credential_id/);
});
