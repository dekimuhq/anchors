import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { aarFamily } from "../src/family.ts";

describe("aarFamily manifest", () => {
  it("has correct chip and status_list_slot", () => {
    assert.strictEqual(aarFamily.meta.chip, 8);
    assert.strictEqual(aarFamily.meta.status_list_slot, 12);
  });

  it("has correct claim_types", () => {
    assert.deepStrictEqual(aarFamily.meta.claim_types, ["ar.attestation.v1"]);
  });

  it("has all 8 profiles registered", () => {
    const profiles = Object.keys(
      Object.fromEntries(
        aarFamily.profileIds.map((id) => [id, true]),
      ),
    );
    assert.strictEqual(profiles.length, 8);
    assert.ok(aarFamily.hasProfile("eidas.qes"));
    assert.ok(aarFamily.hasProfile("eidas.qeseal"));
    assert.ok(aarFamily.hasProfile("eidas.qts"));
    assert.ok(aarFamily.hasProfile("eidas.qereg"));
    assert.ok(aarFamily.hasProfile("eidas.qcert.natural"));
    assert.ok(aarFamily.hasProfile("eidas.qcert.legal"));
    assert.ok(aarFamily.hasProfile("eidas.qwallet"));
    assert.ok(aarFamily.hasProfile("eidas.qattest"));
  });

  it("has continuity enabled", () => {
    assert.strictEqual(aarFamily.meta.continuity, true);
  });

  it("exposes verifyReceipt", () => {
    assert.strictEqual(typeof aarFamily.verifyReceipt, "function");
  });

  it("exposes compose helpers", () => {
    assert.ok(aarFamily.compose !== undefined);
  });
});
