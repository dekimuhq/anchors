/**
 * v=1 backward-compatibility regression tests.
 *
 * Exercises the `verifyReceipt` dispatcher entry points from Tasks 5 / 6 / 6b
 * on deterministic v=1 receipts. Guarantees that v=2 work in Phases B-E
 * cannot silently break v=1 backward compatibility.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyReceipt as verifyApr } from "@dekimuhq/apr";
import { verifyReceipt as verifyAcr } from "@dekimuhq/acr";
import { verifyReceipt as verifyArr } from "@dekimuhq/arr";
import type { ClaimKeyResolver } from "@dekimuhq/apr";
import aprVector from "./vectors-v1-1/apr-v1.ts";
import acrVector from "./vectors-v1-1/acr-consent-v1.ts";
import arrVector from "./vectors-v1-1/arr-erasure-v1.ts";

test("v=1 APR provenance vector still verifies after v1.1 changes", async () => {
  const claimKeyResolver: ClaimKeyResolver = (kid) => {
    if (kid === "apr-v1-regression-kid") {
      return {
        kid: "apr-v1-regression-kid",
        publicKey: aprVector.publicKey,
        issuer: "did:web:test-issuer.example",
      };
    }
    return undefined;
  };

  const result = await verifyApr(aprVector.receipt, {
    v1Opts: { claimKeyResolver },
  });

  assert.equal(result.envelope_version, 1);
  assert.equal(result.signature_valid, true);
});

test("v=1 ACR consent vector still verifies after v1.1 changes", async () => {
  const result = await verifyAcr(acrVector.receipt);

  assert.equal(result.envelope_version, 1);
  assert.equal(result.signature_valid, true);
});

test("v=1 ARR erasure vector still verifies after v1.1 changes", async () => {
  const result = await verifyArr(arrVector.receipt, {
    v1Opts: { anchorInclusionTime: arrVector.anchorInclusionTime },
  });

  assert.equal(result.envelope_version, 1);
  assert.equal(result.signature_valid, true);
});
