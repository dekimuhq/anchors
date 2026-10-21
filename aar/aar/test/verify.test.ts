import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { verifyReceipt } from "../src/index.ts";

describe("verifyReceipt", () => {
  it("rejects non-object input", async () => {
    const r = await verifyReceipt(null);
    assert.strictEqual(r.signature_valid, false);
    assert.strictEqual(r.reason, "schema_invalid");
  });

  it("rejects unsupported envelope version", async () => {
    const r = await verifyReceipt({ v: 1 });
    assert.strictEqual(r.reason, "unsupported_envelope_version");
  });

  it("rejects v=2 receipt without resolveKey", async () => {
    const r = await verifyReceipt({ v: 2, claim_type: "ar.attestation.v1" });
    assert.strictEqual(r.signature_valid, false);
  });
});
