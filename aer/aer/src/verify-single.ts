/**
 * Per-event-type AER body verifier (spec §4 + D10-AER through D15-AER).
 *
 * Validates the discriminated union on `body.event_type` and per-event
 * required-field rules.
 */

import type {
  AerBody,
  AerRiskClass,
  AerAssessmentRoute,
  AerDisclosureScope,
  AerDisclosureType,
  AerWatermarkScheme,
  AerAnnexIiiCategory,
} from "./types.ts";

export interface VerifyBodyResult {
  valid: boolean;
  errors: string[];
  body: AerBody | null;
}

export function verifyAerBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  switch (b.event_type) {
    case "conformity":
      validateConformity(b, errors);
      break;
    case "transparency":
      validateTransparency(b, errors);
      break;
    default:
      errors.push("event_type.unknown");
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AerBody };
}

function validateConformity(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.system_id_commit)) errors.push("system_id_commit.missing");
  if (!isNonEmptyString(b.system_version)) errors.push("system_version.missing");
  if (!isNonEmptyString(b.model_id_commit)) errors.push("model_id_commit.missing");

  if (!isRiskClass(b.risk_class)) {
    errors.push("risk_class.invalid");
  } else if (b.risk_class === "high") {
    if (!Array.isArray(b.annex_iii_categories) || b.annex_iii_categories.length === 0) {
      errors.push("annex_iii_categories.required_when_high_risk");
    } else {
      for (const cat of b.annex_iii_categories) {
        if (!isAnnexIiiCategory(cat)) {
          errors.push("annex_iii_categories.invalid_category");
          break;
        }
      }
    }
  }

  if (!isAssessmentRoute(b.assessment_route)) {
    errors.push("assessment_route.invalid");
  } else {
    if (b.assessment_route === "thirdparty_notified_body" && !isNonEmptyString(b.notified_body_id)) {
      errors.push("notified_body_id.required_when_thirdparty");
    }
    if (b.assessment_route === "fundamental_rights" && !isNonEmptyString(b.fundamental_rights_hash)) {
      errors.push("fundamental_rights_hash.required_when_fr");
    }
  }

  if (!isNonEmptyString(b.tech_doc_hash)) errors.push("tech_doc_hash.missing");
  if (!isNonEmptyString(b.risk_management_system_hash)) errors.push("risk_management_system_hash.missing");
  if (!isNonEmptyString(b.data_governance_hash)) errors.push("data_governance_hash.missing");
  if (!isNonEmptyString(b.valid_from)) errors.push("valid_from.missing");

  if (!Array.isArray(b.harmonized_standards)) {
    errors.push("harmonized_standards.missing");
  }
}

function validateTransparency(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.system_id_commit)) errors.push("system_id_commit.missing");
  if (!isNonEmptyString(b.conformity_receipt_hash)) errors.push("conformity_receipt_hash.missing");
  if (!isNonEmptyString(b.subject_commit)) errors.push("subject_commit.missing");

  if (!isDisclosureScope(b.disclosure_scope)) errors.push("disclosure_scope.invalid");
  if (!isDisclosureType(b.disclosure_type)) errors.push("disclosure_type.invalid");
  if (!isNonEmptyString(b.disclosure_text_hash)) errors.push("disclosure_text_hash.missing");
  if (!isNonEmptyString(b.disclosure_locale)) errors.push("disclosure_locale.missing");
  if (!isNonEmptyString(b.interaction_window_start)) errors.push("interaction_window_start.missing");
  if (!isNonEmptyString(b.interaction_window_end)) errors.push("interaction_window_end.missing");

  if (!isWatermarkScheme(b.watermark_scheme)) {
    errors.push("watermark_scheme.invalid");
  } else if (b.watermark_scheme !== "none" && !isNonEmptyString(b.watermark_sample_commit)) {
    errors.push("watermark_sample_commit.required_when_watermarked");
  }
}

const RISK_CLASSES = new Set<string>(["prohibited", "high", "limited", "minimal", "gpai", "gpai_systemic"]);
const ASSESSMENT_ROUTES = new Set<string>(["internal_control", "thirdparty_notified_body", "fundamental_rights"]);
const ANNEX_III = new Set<string>([
  "biometrics", "critical_infrastructure", "education_training", "employment_management",
  "essential_services", "law_enforcement", "migration_border", "justice_democratic",
]);
const DISCLOSURE_SCOPES = new Set<string>(["single", "session", "batch"]);
const DISCLOSURE_TYPES = new Set<string>([
  "chatbot", "synthetic_audio", "synthetic_image", "synthetic_video",
  "deepfake_recognisable_person", "deepfake_artistic", "emotion_recognition",
  "biometric_categorisation", "ai_generated_text_public_interest",
]);
const WATERMARK_SCHEMES = new Set<string>(["c2pa", "starc", "nlsw", "none"]);

function isRiskClass(v: unknown): v is AerRiskClass {
  return typeof v === "string" && RISK_CLASSES.has(v);
}
function isAssessmentRoute(v: unknown): v is AerAssessmentRoute {
  return typeof v === "string" && ASSESSMENT_ROUTES.has(v);
}
function isAnnexIiiCategory(v: unknown): v is AerAnnexIiiCategory {
  return typeof v === "string" && ANNEX_III.has(v);
}
function isDisclosureScope(v: unknown): v is AerDisclosureScope {
  return typeof v === "string" && DISCLOSURE_SCOPES.has(v);
}
function isDisclosureType(v: unknown): v is AerDisclosureType {
  return typeof v === "string" && DISCLOSURE_TYPES.has(v);
}
function isWatermarkScheme(v: unknown): v is AerWatermarkScheme {
  return typeof v === "string" && WATERMARK_SCHEMES.has(v);
}
function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

export type { AerConformityBody, AerTransparencyBody } from "./types.ts";
