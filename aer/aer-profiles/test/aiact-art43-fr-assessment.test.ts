import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateAiactArt43FrAssessment } from "../src/aiact-art43-fr-assessment.ts";

function makeConformity(overrides?: Record<string, unknown>) {
  return {
    event_type: "conformity",
    profile: "aiact.art43.fr_assessment",
    system_id_commit: "sha256:abc",
    system_version: "1.0.0",
    model_id_commit: "sha256:def",
    risk_class: "high",
    annex_iii_categories: ["law_enforcement"],
    assessment_route: "fundamental_rights",
    notified_body_id: null,
    harmonized_standards: [],
    tech_doc_hash: "sha256:aaa",
    tech_doc_arr_receipt_hash: null,
    risk_management_system_hash: "sha256:bbb",
    data_governance_hash: "sha256:ccc",
    fundamental_rights_hash: "sha256:frh",
    training_atr_arrangement_hash: null,
    training_apur_binding_hash: null,
    valid_from: "2026-08-02T00:00:00Z",
    valid_until: "2028-08-02T00:00:00Z",
    ...overrides,
  };
}

describe("validateAiactArt43FrAssessment", () => {
  it("accepts a valid FRIA conformity receipt", () => {
    const result = validateAiactArt43FrAssessment(makeConformity() as never);
    assert.deepEqual(result.errors, []);
  });

  it("rejects wrong event_type", () => {
    const result = validateAiactArt43FrAssessment(makeConformity({ event_type: "transparency" }) as never);
    assert.ok(result.errors.includes("aiact.art43.fr_assessment.wrong_event_type"));
  });

  it("rejects wrong assessment_route", () => {
    const result = validateAiactArt43FrAssessment(makeConformity({ assessment_route: "internal_control" }) as never);
    assert.ok(result.errors.includes("aiact.art43.fr_assessment.wrong_assessment_route"));
  });

  it("rejects null fundamental_rights_hash", () => {
    const result = validateAiactArt43FrAssessment(makeConformity({ fundamental_rights_hash: null }) as never);
    assert.ok(result.errors.includes("aiact.art43.fr_assessment.fundamental_rights_hash_missing"));
  });

  it("rejects empty fundamental_rights_hash", () => {
    const result = validateAiactArt43FrAssessment(makeConformity({ fundamental_rights_hash: "" }) as never);
    assert.ok(result.errors.includes("aiact.art43.fr_assessment.fundamental_rights_hash_missing"));
  });
});
