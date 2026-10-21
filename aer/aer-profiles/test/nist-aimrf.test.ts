import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateNistAimrf } from "../src/nist-aimrf.ts";

function makeConformity(overrides?: Record<string, unknown>) {
  return {
    event_type: "conformity",
    profile: "nist.aimrf.profile",
    system_id_commit: "sha256:abc",
    system_version: "1.0.0",
    model_id_commit: "sha256:def",
    risk_class: "high",
    annex_iii_categories: ["employment_management"],
    assessment_route: "internal_control",
    notified_body_id: null,
    harmonized_standards: [],
    tech_doc_hash: "sha256:aaa",
    tech_doc_arr_receipt_hash: null,
    risk_management_system_hash: "sha256:bbb",
    data_governance_hash: "sha256:ccc",
    fundamental_rights_hash: null,
    training_atr_arrangement_hash: null,
    training_apur_binding_hash: null,
    valid_from: "2026-08-02T00:00:00Z",
    valid_until: "2028-08-02T00:00:00Z",
    ...overrides,
  };
}

describe("validateNistAimrf", () => {
  it("accepts a valid NIST AI RMF crosswalk receipt", () => {
    const result = validateNistAimrf(makeConformity() as never);
    assert.deepEqual(result.errors, []);
  });

  it("accepts any risk_class (informational profile has no risk_class constraint)", () => {
    const classes = ["high", "limited", "minimal", "gpai", "gpai_systemic"];
    for (const risk_class of classes) {
      const result = validateNistAimrf(makeConformity({ risk_class }) as never);
      assert.deepEqual(result.errors, [], `risk_class=${risk_class} should be accepted`);
    }
  });

  it("rejects wrong event_type (transparency)", () => {
    const result = validateNistAimrf(makeConformity({ event_type: "transparency" }) as never);
    assert.ok(result.errors.includes("nist.aimrf.profile.wrong_event_type"));
  });

  it("accumulates only event_type error on wrong type", () => {
    const result = validateNistAimrf(makeConformity({ event_type: "transparency" }) as never);
    assert.equal(result.errors.length, 1);
  });
});
