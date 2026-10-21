import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { aerFamily } from "../src/family.ts";

describe("aerFamily manifest", () => {
  it("has correct acronym", () => {
    assert.strictEqual(aerFamily.meta.acronym, "AER");
  });

  it("has correct claim_types", () => {
    assert.deepStrictEqual(aerFamily.meta.claim_types, ["ar.evaluation.v1"]);
  });

  it("has chip 7", () => {
    assert.strictEqual(aerFamily.meta.chip, 7);
  });

  it("has status_list_slot 11", () => {
    assert.strictEqual(aerFamily.meta.status_list_slot, 11);
  });

  it("has TSA mandate for conformity as optional (no profiles registered yet)", () => {
    // tsa_mandate is profile-keyed; no profiles registered until Task 10.
    // conformity is event-keyed — enforced via composeAer, not the factory matrix.
    assert.strictEqual(aerFamily.tsaMandateLevel("conformity"), "optional");
  });

  it("has continuity enabled", () => {
    assert.strictEqual(aerFamily.meta.continuity, true);
  });

  it("exposes verifyReceipt function", () => {
    assert.strictEqual(typeof aerFamily.verifyReceipt, "function");
  });
});
