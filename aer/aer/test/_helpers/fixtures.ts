import { randomBytes } from "node:crypto";
import type { AerConformityBody, AerTransparencyBody } from "../../src/types.ts";

export function sha256Hex(): string {
  return `sha256:${randomBytes(32).toString("hex")}`;
}

export function makeConformityBody(
  overrides?: Partial<AerConformityBody>,
): AerConformityBody {
  return {
    event_type: "conformity",
    profile: "aiact.art43.internal",
    system_id_commit: sha256Hex(),
    system_version: "1.0.0",
    model_id_commit: sha256Hex(),
    risk_class: "high",
    annex_iii_categories: ["education_training"],
    assessment_route: "internal_control",
    notified_body_id: null,
    harmonized_standards: ["ISO/IEC 42001:2023"],
    tech_doc_hash: sha256Hex(),
    tech_doc_arr_receipt_hash: null,
    risk_management_system_hash: sha256Hex(),
    data_governance_hash: sha256Hex(),
    fundamental_rights_hash: null,
    training_atr_arrangement_hash: null,
    training_apur_binding_hash: null,
    valid_from: "2026-08-02T00:00:00Z",
    valid_until: "2028-08-02T00:00:00Z",
    qts_attestation_hash: null,
    ...overrides,
  };
}

export function makeTransparencyBody(
  overrides?: Partial<AerTransparencyBody>,
): AerTransparencyBody {
  return {
    event_type: "transparency",
    profile: "aiact.art50.chatbot",
    system_id_commit: sha256Hex(),
    system_apr_kid: null,
    conformity_receipt_hash: sha256Hex(),
    subject_commit: sha256Hex(),
    disclosure_scope: "session",
    disclosure_type: "chatbot",
    disclosure_text_hash: sha256Hex(),
    disclosure_locale: "en-GB",
    interaction_window_start: "2026-09-01T10:00:00Z",
    interaction_window_end: "2026-09-01T10:15:00Z",
    artifact_apr_hash: null,
    oversight_acr_hash: null,
    watermark_scheme: "none",
    watermark_sample_commit: null,
    qts_attestation_hash: null,
    ...overrides,
  };
}
