/**
 * `aiact.art14.oversight` profile validator — ADR spec section 5.
 *
 * Hook: AI Act Art. 14 oversight assignment. The delegation receipt MUST
 * declare oversight_scope, an escalation URI, and MUST NOT be delegable.
 *
 * v1 invariants enforced here (grant events only):
 *   - `body.scope.constraints.oversight_scope` MUST be one of:
 *     "pre-approval", "post-review", "intervention-only", "continuous".
 *   - `body.scope.constraints.escalation_uri` MUST be a non-empty string.
 *   - `body.delegable` MUST be false.
 */

import type { AdrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART14_OVERSIGHT_PROFILE_ID = "aiact.art14.oversight" as const;

const VALID_OVERSIGHT_SCOPES = new Set([
  "pre-approval",
  "post-review",
  "intervention-only",
  "continuous",
]);

export function validateAiactArt14Oversight(body: AdrBody): ProfileValidationResult {
  const errors: string[] = [];
  if (body.event !== "grant") return { errors };

  const b = body as unknown as Record<string, unknown>;

  // scope.constraints.oversight_scope
  const scope = b["scope"] as Record<string, unknown> | undefined;
  const constraints = scope?.["constraints"] as Record<string, unknown> | undefined;
  const oversightScope = constraints?.["oversight_scope"];
  if (typeof oversightScope !== "string" || !VALID_OVERSIGHT_SCOPES.has(oversightScope)) {
    errors.push("aiact.art14.oversight.oversight_scope_invalid");
  }

  // scope.constraints.escalation_uri
  if (typeof constraints?.["escalation_uri"] !== "string" || constraints["escalation_uri"] === "") {
    errors.push("aiact.art14.oversight.escalation_uri_missing");
  }

  // delegable must be false
  if (b["delegable"] !== false) {
    errors.push("aiact.art14.oversight.delegable_must_be_false");
  }

  return { errors };
}

export const validateAiactArt14OversightProfile = makeProfileAdapter(
  AIACT_ART14_OVERSIGHT_PROFILE_ID,
  (body) => validateAiactArt14Oversight(body as AdrBody),
);
