import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateAiactArt43Thirdparty } from "../src/aiact-art43-thirdparty.ts";

function makeConformity(overrides?: Record<string, unknown>) {
  return {
    event_type: "conformity",
    profile: "aiact.art43.thirdparty",
    system_id_commit: "sha256:abc",
    system_version: "1.0.0",
    model_id_commit: "sha256:def",
    risk_class: "high",
    annex_iii_categories: ["biometrics"],
    assessment_route: "thirdparty_notified_body",
    notified_body_id: "NB-1234",
    harmonized_standards: ["ISO/IEC 42001:2023", "EN 301 549"],
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

describe("validateAiactArt43Thirdparty", () => {
  it("accepts a valid third-party conformity receipt", () => {
    const result = validateAiactArt43Thirdparty(makeConformity() as never);
    assert.deepEqual(result.errors, []);
  });

  it("rejects wrong event_type", () => {
    const result = validateAiactArt43Thirdparty(makeConformity({ event_type: "transparency" }) as never);
    assert.ok(result.errors.includes("aiact.art43.thirdparty.wrong_event_type"));
  });

  it("rejects wrong assessment_route", () => {
    const result = validateAiactArt43Thirdparty(makeConformity({ assessment_route: "internal_control" }) as never);
    assert.ok(result.errors.includes("aiact.art43.thirdparty.wrong_assessment_route"));
  });

  it("rejects null notified_body_id", () => {
    const result = validateAiactArt43Thirdparty(makeConformity({ notified_body_id: null }) as never);
    assert.ok(result.errors.includes("aiact.art43.thirdparty.notified_body_id_invalid"));
  });

  it("rejects malformed notified_body_id (wrong pattern)", () => {
    const result = validateAiactArt43Thirdparty(makeConformity({ notified_body_id: "NB-12" }) as never);
    assert.ok(result.errors.includes("aiact.art43.thirdparty.notified_body_id_invalid"));
  });

  it("rejects empty harmonized_standards", () => {
    const result = validateAiactArt43Thirdparty(makeConformity({ harmonized_standards: [] }) as never);
    assert.ok(result.errors.includes("aiact.art43.thirdparty.harmonized_standards_empty"));
  });
});
