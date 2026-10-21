/**
 * `aiact.art52.gpai` profile validator — AER spec §5.8.
 *
 * GPAI provider transparency (AI Act Art 52 + Arts 53–55).
 * General Purpose AI model providers must maintain technical documentation.
 *
 * v1 invariants enforced here:
 *   - `body.event_type === "conformity"` (Art 52 = documentation, not per-interaction)
 *   - `body.risk_class` ∈ {gpai, gpai_systemic}
 *   - `body.tech_doc_hash` non-empty
 */

import type { AerBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART52_GPAI_PROFILE_ID = "aiact.art52.gpai" as const;

const GPAI_RISK_CLASSES = new Set(["gpai", "gpai_systemic"]);

export function validateAiactArt52Gpai(body: AerBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "conformity") {
    errors.push("aiact.art52.gpai.wrong_event_type");
    return { errors };
  }

  if (!GPAI_RISK_CLASSES.has(body.risk_class)) {
    errors.push("aiact.art52.gpai.wrong_risk_class");
  }

  if (typeof body.tech_doc_hash !== "string" || body.tech_doc_hash.trim() === "") {
    errors.push("aiact.art52.gpai.tech_doc_hash_missing");
  }

  return { errors };
}

export const validateAiactArt52GpaiProfile = makeProfileAdapter(
  AIACT_ART52_GPAI_PROFILE_ID,
  (body) => validateAiactArt52Gpai(body as AerBody),
);
