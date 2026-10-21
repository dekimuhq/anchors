/**
 * `gdpr.art13.transparency` profile validator — ALR spec §5.1.
 *
 * Hook: GDPR Art 13(1)(e), Art 13(2)(f). Controller-driven transparency
 * receipts where the subject must be informed of recipients or of automated
 * decision-making logic.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"gdpr.art13.transparency"`.
 *   - `body.event_type` MUST be one of `derived_from`, `forked_from`,
 *     `disclosed`.
 *
 * Subject-presence (envelope.subject) and structural body rules (parents
 * shape, transform_claim, disclosure block) are handled by the verifier's
 * §E + §C passes and are deliberately NOT re-checked here.
 *
 * Spec extras `data_categories[]` + body-level `sub_commit` are documented
 * in §5.1 but are not represented in the typed `AlrBody` for v1.0 (spec
 * §10.2 roadmap). When those fields land in `AlrBody`, this validator
 * extends to enforce them.
 */

import type { AlrBody, AlrEventType } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART13_TRANSPARENCY_PROFILE_ID =
  "gdpr.art13.transparency" as const;

const ALLOWED_EVENT_TYPES: ReadonlySet<AlrEventType> = new Set([
  "derived_from",
  "forked_from",
  "disclosed",
]);

/**
 * Pure validator. Returns the collected `errors[]` — empty when valid.
 */
export function validateGdprArt13Transparency(
  body: AlrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== GDPR_ART13_TRANSPARENCY_PROFILE_ID) {
    errors.push("gdpr.art13.transparency.profile.mismatch");
    return { errors };
  }

  if (!ALLOWED_EVENT_TYPES.has(body.event_type)) {
    errors.push("gdpr.art13.transparency.event_type.disallowed");
  }

  return { errors };
}

export const validateGdprArt13TransparencyProfile = makeProfileAdapter(GDPR_ART13_TRANSPARENCY_PROFILE_ID, (body) => validateGdprArt13Transparency(body as AlrBody));
