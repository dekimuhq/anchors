/**
 * Cross-issuer trustedLogs conformance vectors (Task 12 of the v1.1 cross-
 * issuer interop plan). Three ACR cases cover the meaningful branches of the
 * verifier-side allowlist:
 *
 *   1. trustedLogs set + matching anchor.log → pass
 *   2. trustedLogs set + mismatching anchor.log → fail with reason=untrusted_log
 *   3. trustedLogs absent → unchanged behavior (untrusted log still accepted)
 *
 * Mirrors anchors/acr/acr-verifier/test/envelope-v2-trusted-logs.test.ts but
 * runs from the e2e workspace against the published `@dekimuhq/acr-verifier`,
 * proving the allowlist surface is reachable end-to-end (not just inside the
 * verifier's own tests). The full 5-branch matrix (incl. no-anchor + empty-set)
 * lives in the verifier package; e2e ships the cross-issuer-relevant subset.
 *
 * trustedLogs is a verifier-side option, not receipt-side, so this test is
 * written directly in TypeScript rather than as a JSON vector — vectorising
 * adds zero confidence over a freshly-signed receipt (plan Task 12 Step 1
 * explicitly permits this approach).
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { verifyReceipt as verifyReceiptRaw } from "@dekimuhq/acr";
import type { EnvelopeVerifyResult } from "@dekimuhq/acr";
import {
  makeValidV2AcrReceipt,
  makeResolveKey,
} from "./_helpers/v2-receipt-acr.ts";

const TRUSTED = "https://verify.dekimu.com/acr/v1";
const UNTRUSTED = "https://attacker.example/acr/v1";

/**
 * `verifyReceipt` returns a `v=1 | v=2 | unknown` union; every receipt here is
 * v=2, so narrow to the v=2 result. Wrapped so the call sites stay unchanged.
 */
function v2(r: Awaited<ReturnType<typeof verifyReceiptRaw>>): EnvelopeVerifyResult {
  if (r.envelope_version !== 2) {
    assert.fail(`expected v=2 verify result, got ${String(r.envelope_version)}`);
  }
  return r;
}
const verifyReceipt = (
  receipt: unknown,
  opts?: Parameters<typeof verifyReceiptRaw>[1],
): Promise<EnvelopeVerifyResult> => verifyReceiptRaw(receipt, opts).then(v2);

describe("cross-issuer trustedLogs conformance vectors (ACR)", () => {
  it("acr-trusted-log-match — matching anchor.log passes", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({
      anchorLog: TRUSTED,
    });
    const r = await verifyReceipt(receipt, {
      resolveKey: makeResolveKey(pub),
      trustedLogs: new Set([TRUSTED]),
    });
    assert.equal(r.signature_valid, true);
  });

  it("acr-trusted-log-mismatch — untrusted anchor.log → reason=untrusted_log", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({
      anchorLog: UNTRUSTED,
    });
    const r = await verifyReceipt(receipt, {
      resolveKey: makeResolveKey(pub),
      trustedLogs: new Set([TRUSTED]),
    });
    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "untrusted_log");
    assert.equal(r.claim_type, receipt.claim_type);
  });

  it("acr-untrusted-log-no-allowlist — absent option leaves behavior unchanged", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({
      anchorLog: UNTRUSTED,
    });
    const r = await verifyReceipt(receipt, {
      resolveKey: makeResolveKey(pub),
    });
    assert.equal(r.signature_valid, true);
  });
});
