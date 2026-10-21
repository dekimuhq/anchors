/**
 * ARR verifyReceipt — trustedLogs allowlist option (cross-issuer interop Item 2).
 *
 * Five branches: absent (legacy) / matching / mismatching / no-anchor /
 * empty-set. Gate runs after signature check but before policy / status / TSA /
 * profile dispatch. Helper uses `ar.batch.v1` (policy-exempt) so the
 * absent-allowlist test reaches signature_valid=true cleanly.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";
import { makeValidV2Receipt, makeResolveKey } from "./_helpers/v2-receipt.ts";

const TRUSTED = "https://verify.dekimu.com/arr/v1";
const UNTRUSTED = "https://attacker.example/arr/v1";

describe("ARR verifyReceipt — trustedLogs option", () => {
  it("absent trustedLogs → unchanged behavior (any log accepted)", async () => {
    const { receipt, pub } = await makeValidV2Receipt({ anchorLog: UNTRUSTED });
    const r = await verifyReceipt(receipt, { resolveKey: makeResolveKey(pub) });
    assert.equal(r.signature_valid, true);
  });

  it("trustedLogs set + matching → pass", async () => {
    const { receipt, pub } = await makeValidV2Receipt({ anchorLog: TRUSTED });
    const r = await verifyReceipt(receipt, {
      resolveKey: makeResolveKey(pub),
      trustedLogs: new Set([TRUSTED]),
    });
    assert.equal(r.signature_valid, true);
  });

  it("trustedLogs set + mismatch → signature_valid=false, reason=untrusted_log", async () => {
    const { receipt, pub } = await makeValidV2Receipt({ anchorLog: UNTRUSTED });
    const r = await verifyReceipt(receipt, {
      resolveKey: makeResolveKey(pub),
      trustedLogs: new Set([TRUSTED]),
    }) as FamilyVerifyResult;
    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "untrusted_log");
    assert.equal(r.claim_type, receipt.claim_type);
  });

  it("trustedLogs set + receipt has no anchor → signature_valid=false, reason=untrusted_log", async () => {
    const { receipt, pub } = await makeValidV2Receipt({ anchorLog: undefined });
    const r = await verifyReceipt(receipt, {
      resolveKey: makeResolveKey(pub),
      trustedLogs: new Set([TRUSTED]),
    });
    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "untrusted_log");
  });

  it("empty trustedLogs set → every receipt rejected", async () => {
    const { receipt, pub } = await makeValidV2Receipt({ anchorLog: TRUSTED });
    const r = await verifyReceipt(receipt, {
      resolveKey: makeResolveKey(pub),
      trustedLogs: new Set<string>(),
    });
    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "untrusted_log");
  });
});
