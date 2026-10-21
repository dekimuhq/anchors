import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateAiactArt52Gpai } from "../src/aiact-art52-gpai.ts";

function makeConformity(overrides?: Record<string, unknown>) {
  return {
    event_type: "conformity",
    profile: "aiact.art52.gpai",
    system_id_commit: "sha256:abc",
    system_version: "1.0.0",
    model_id_commit: "sha256:def",
    risk_class: "gpai",
    annex_iii_categories: null,
    assessment_route: "internal_control",
    notified_body_id: null,
    harmonized_standards: [],
    tech_doc_hash: "sha256:techdoc",
    tech_doc_arr_receipt_hash: null,
    risk_management_system_hash: "sha256:rms",
    data_governance_hash: "sha256:dgh",
    fundamental_rights_hash: null,
    training_atr_arrangement_hash: null,
    training_apur_binding_hash: null,
    valid_from: "2026-08-02T00:00:00Z",
    valid_until: null,
    ...overrides,
  };
}

describe("validateAiactArt52Gpai", () => {
  it("accepts a valid GPAI transparency receipt", () => {
    const result = validateAiactArt52Gpai(makeConformity() as never);
    assert.deepEqual(result.errors, []);
  });

  it("accepts gpai_systemic risk class", () => {
    const result = validateAiactArt52Gpai(makeConformity({ risk_class: "gpai_systemic" }) as never);
    assert.deepEqual(result.errors, []);
  });

  it("rejects wrong event_type", () => {
    const result = validateAiactArt52Gpai(makeConformity({ event_type: "transparency" }) as never);
    assert.ok(result.errors.includes("aiact.art52.gpai.wrong_event_type"));
  });

  it("rejects high risk_class (not GPAI)", () => {
    const result = validateAiactArt52Gpai(makeConformity({ risk_class: "high" }) as never);
    assert.ok(result.errors.includes("aiact.art52.gpai.wrong_risk_class"));
  });

  it("rejects empty tech_doc_hash", () => {
    const result = validateAiactArt52Gpai(makeConformity({ tech_doc_hash: "" }) as never);
    assert.ok(result.errors.includes("aiact.art52.gpai.tech_doc_hash_missing"));
  });
});
