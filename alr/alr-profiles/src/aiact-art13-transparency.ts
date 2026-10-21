/**
 * `aiact.art13.transparency` profile validator — ALR spec §5.2.
 *
 * Hook: EU AI Act Art 13. High-risk AI systems must enable users to
 * interpret outputs; lineage receipts under this profile pin the training/
 * forking events that produced a deployed model.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"aiact.art13.transparency"`.
 *   - `body.event_type` MUST be one of `derived_from`, `forked_from`,
 *     `superseded_by` (spec §5.2 disallows `disclosed`).
 *   - When `event_type === "derived_from"`: `body.transform_claim.summary`
 *     MUST mention one of the five training-method classes:
 *       `pretrain`, `fine-tune`, `distillation`, `merge`, `quantize`.
 *     Match is whole-word, case-insensitive, hyphen-aware.
 *
 * Spec extras `system_id` + `risk_classification` (§5.2 row 3) are not
 * represented in the typed `AlrBody` for v1.0; they land in v1.1.
 */

import type { AlrBody, AlrEventType } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART13_TRANSPARENCY_PROFILE_ID =
  "aiact.art13.transparency" as const;

const ALLOWED_EVENT_TYPES: ReadonlySet<AlrEventType> = new Set([
  "derived_from",
  "forked_from",
  "superseded_by",
]);

/**
 * Whole-word, case-insensitive, hyphen-aware match for any of the five
 * training-method classes. Anchored on `\b` boundaries so `pretraining`
 * matches `pretrain`, but `prefine-tuner` does NOT match `fine-tune` alone.
 */
const TRAINING_METHOD_REGEX =
  /\b(pretrain(?:ing|ed)?|fine[- ]?tun(?:e|ed|ing)|distillation|merge[ds]?|quantiz(?:e|ed|ation))\b/i;

export function validateAiactArt13Transparency(
  body: AlrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== AIACT_ART13_TRANSPARENCY_PROFILE_ID) {
    errors.push("aiact.art13.transparency.profile.mismatch");
    return { errors };
  }

  if (!ALLOWED_EVENT_TYPES.has(body.event_type)) {
    errors.push("aiact.art13.transparency.event_type.disallowed");
  }

  if (body.event_type === "derived_from") {
    const summary = body.transform_claim?.summary ?? "";
    if (!TRAINING_METHOD_REGEX.test(summary)) {
      errors.push("aiact.art13.transparency.transform_claim.method_missing");
    }
  }

  return { errors };
}

export const validateAiactArt13TransparencyProfile = makeProfileAdapter(AIACT_ART13_TRANSPARENCY_PROFILE_ID, (body) => validateAiactArt13Transparency(body as AlrBody));
