/**
 * `hub.automation` profile validator — AActR spec §5.
 *
 * The only issuer of AActR v1 is the Dekimu Hub automations engine. This
 * profile asserts the structural invariants of a Hub-automation action receipt:
 *
 *   - `body.profile === "hub.automation"`
 *   - `body.verb` matches the engine verb-allowlist shape `<ns>.<op>`
 *   - `body.outcome ∈ {executed, failed-gave-up}`
 *   - `body.rule_id` / `body.recipe_id` non-empty
 *   - `body.decision_commit` / `params_commit` / `request_id_commit` are
 *     well-formed `sha256:<64-hex>` commits
 *   - `body.executed_at` is a non-empty ISO 8601 string
 */

import type { AActRBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const HUB_AUTOMATION_PROFILE_ID = "hub.automation" as const;

/**
 * Engine verb-allowlist shape: dot-separated segments, `<ns>.<op>`. Each segment is
 * lowercase-alphanumeric and MAY contain internal hyphens (kebab-case ops, e.g.
 * `operator.draft-reminder`) — a hyphen must sit between two alphanumerics, so no
 * leading/trailing/double hyphen. Matches the engine's real capability ids.
 */
const VERB_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+$/;
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;
const OUTCOMES = new Set<string>(["executed", "failed-gave-up"]);

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

export function validateHubAutomation(
  body: AActRBody
): ProfileValidationResult {
  const errors: string[] = [];
  const b = body as unknown as Record<string, unknown>;

  if (b.profile !== "hub.automation") {
    errors.push("hub.automation.wrong_profile");
  }

  if (!isNonEmptyString(b.verb)) {
    errors.push("hub.automation.verb_missing");
  } else if (!VERB_RE.test(b.verb)) {
    errors.push("hub.automation.verb_malformed");
  }

  if (typeof b.outcome !== "string" || !OUTCOMES.has(b.outcome)) {
    errors.push("hub.automation.outcome_invalid");
  }

  if (!isNonEmptyString(b.rule_id)) {
    errors.push("hub.automation.rule_id_missing");
  }

  if (!isNonEmptyString(b.recipe_id)) {
    errors.push("hub.automation.recipe_id_missing");
  }

  if (!isNonEmptyString(b.executed_at)) {
    errors.push("hub.automation.executed_at_missing");
  }

  if (
    typeof b.decision_commit !== "string" ||
    !SHA256_HEX_RE.test(b.decision_commit)
  ) {
    errors.push("hub.automation.decision_commit_malformed");
  }
  if (
    typeof b.params_commit !== "string" ||
    !SHA256_HEX_RE.test(b.params_commit)
  ) {
    errors.push("hub.automation.params_commit_malformed");
  }
  if (
    typeof b.request_id_commit !== "string" ||
    !SHA256_HEX_RE.test(b.request_id_commit)
  ) {
    errors.push("hub.automation.request_id_commit_malformed");
  }

  return { errors };
}

export const validateHubAutomationProfile = makeProfileAdapter(
  HUB_AUTOMATION_PROFILE_ID,
  (body) => validateHubAutomation(body as AActRBody)
);
