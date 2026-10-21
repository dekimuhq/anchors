/**
 * `purpose.gdpr.art5` profile validator — APuR spec §5.1.
 *
 * Hook: GDPR Art 5(1)(b) — purpose limitation. Applies to binding and
 * unbinding events only; repurpose events must use `purpose.gdpr.art6_4`.
 *
 * v1 invariants enforced here:
 *   - `lawful_basis` must be a recognised Art 6(1) basis.
 *   - `data_categories` must be a non-empty array.
 *   - `data_subjects_class` must be a known enum value.
 *   - `purpose_class` must be namespaced under "gdpr:".
 *   - Event type must be "binding" or "unbinding" — repurpose is rejected.
 */

import type { ApurBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART5_PROFILE_ID = "purpose.gdpr.art5" as const;

const LAWFUL_BASES = new Set([
  "6(1)(a)",
  "6(1)(b)",
  "6(1)(c)",
  "6(1)(d)",
  "6(1)(e)",
  "6(1)(f)",
]);

const DATA_SUBJECTS_CLASSES = new Set([
  "customers",
  "employees",
  "prospects",
  "minors",
  "vulnerable",
  "vendors",
  "visitors",
  "mixed",
]);

export function validateGdprArt5(body: ApurBody): ProfileValidationResult {
  const errors: string[] = [];

  const b = body as unknown as Record<string, unknown>;

  if (b["event_type"] === "repurpose") {
    errors.push("purpose.gdpr.art5.wrong_event_type");
    return { errors };
  }

  // Field validation only applies to binding bodies — unbinding has no
  // purpose/lawful-basis fields.
  if (b["event_type"] !== "binding") {
    return { errors };
  }

  const lawfulBasis = b["lawful_basis"];
  if (typeof lawfulBasis !== "string" || !LAWFUL_BASES.has(lawfulBasis)) {
    errors.push("purpose.gdpr.art5.lawful_basis_invalid");
  }

  const dataCategories = b["data_categories"];
  if (
    !Array.isArray(dataCategories) ||
    (dataCategories as unknown[]).length === 0
  ) {
    errors.push("purpose.gdpr.art5.data_categories_empty");
  }

  const dataSubjectsClass = b["data_subjects_class"];
  if (
    typeof dataSubjectsClass !== "string" ||
    !DATA_SUBJECTS_CLASSES.has(dataSubjectsClass)
  ) {
    errors.push("purpose.gdpr.art5.data_subjects_class_unknown");
  }

  const purposeClass = b["purpose_class"];
  if (
    typeof purposeClass !== "string" ||
    !purposeClass.startsWith("gdpr:")
  ) {
    errors.push("purpose.gdpr.art5.purpose_class_namespace");
  }

  return { errors };
}

export const validateGdprArt5Profile = makeProfileAdapter(
  GDPR_ART5_PROFILE_ID,
  (body) => validateGdprArt5(body as ApurBody),
);
