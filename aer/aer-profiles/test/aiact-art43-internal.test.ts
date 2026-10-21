import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateAiactArt43Internal } from "../src/aiact-art43-internal.ts";

function makeConformity(overrides?: Record<string, unknown>) {
  return {
    event_type: "conformity",
    profile: "aiact.art43.internal",
    system_id_commit: "sha256:abc",
    system_version: "1.0.0",
    model_id_commit: "sha256:def",
    risk_class: "high",
    annex_iii_categories: ["education_training"],
    assessment_route: "internal_control",
    notified_body_id: null,
    harmonized_standards: ["ISO/IEC 42001:2023"],
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

describe("validateAiactArt43Internal", () => {
  it("accepts a valid internal control conformity receipt", () => {
    const result = validateAiactArt43Internal(makeConformity() as never);
    assert.deepEqual(result.errors, []);
  });

  it("rejects wrong event_type", () => {
    const result = validateAiactArt43Internal(makeConformity({ event_type: "transparency" }) as never);
    assert.ok(result.errors.includes("aiact.art43.internal.wrong_event_type"));
  });

  it("rejects wrong assessment_route", () => {
    const result = validateAiactArt43Internal(makeConformity({ assessment_route: "thirdparty_notified_body" }) as never);
    assert.ok(result.errors.includes("aiact.art43.internal.wrong_assessment_route"));
  });

  it("rejects non-null notified_body_id", () => {
    const result = validateAiactArt43Internal(makeConformity({ notified_body_id: "NB-1234" }) as never);
    assert.ok(result.errors.includes("aiact.art43.internal.notified_body_id_must_be_null"));
  });

  it("rejects missing risk_management_system_hash", () => {
    const result = validateAiactArt43Internal(makeConformity({ risk_management_system_hash: "" }) as never);
    assert.ok(result.errors.includes("aiact.art43.internal.risk_management_system_hash_missing"));
  });

  it("rejects missing data_governance_hash", () => {
    const result = validateAiactArt43Internal(makeConformity({ data_governance_hash: "" }) as never);
    assert.ok(result.errors.includes("aiact.art43.internal.data_governance_hash_missing"));
  });
});
