/**
 * `aiact.art26.deployer` profile validator — ADR spec section 5.
 *
 * Hook: AI Act Art. 26 deployer obligation. The delegation receipt MUST
 * attest the agent descriptor (model, model_version, tool_set_hash),
 * a human oversight URI, and an incident reporting URI.
 *
 * v1 invariants enforced here (grant events only):
 *   - `body.agent.agent_descriptor` MUST be present with model, model_version, tool_set_hash.
 *   - `body.scope.constraints.human_oversight_uri` MUST be a non-empty string.
 *   - `body.scope.constraints.incident_reporting_uri` MUST be a non-empty string.
 */

import type { AdrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART26_DEPLOYER_PROFILE_ID = "aiact.art26.deployer" as const;

export function validateAiactArt26Deployer(body: AdrBody): ProfileValidationResult {
  const errors: string[] = [];
  if (body.event !== "grant") return { errors };

  const b = body as unknown as Record<string, unknown>;

  // agent_descriptor must be present with model, model_version, tool_set_hash
  const agent = b["agent"] as Record<string, unknown> | undefined;
  const desc = agent?.["agent_descriptor"] as Record<string, unknown> | undefined;
  if (!desc || typeof desc !== "object") {
    errors.push("aiact.art26.deployer.agent_descriptor_missing");
  } else {
    if (typeof desc["model"] !== "string" || desc["model"] === "") {
      errors.push("aiact.art26.deployer.agent_descriptor_model_missing");
    }
    if (typeof desc["model_version"] !== "string" || desc["model_version"] === "") {
      errors.push("aiact.art26.deployer.agent_descriptor_model_version_missing");
    }
    if (typeof desc["tool_set_hash"] !== "string" || desc["tool_set_hash"] === "") {
      errors.push("aiact.art26.deployer.agent_descriptor_tool_set_hash_missing");
    }
  }

  // scope.constraints.human_oversight_uri
  const scope = b["scope"] as Record<string, unknown> | undefined;
  const constraints = scope?.["constraints"] as Record<string, unknown> | undefined;
  if (typeof constraints?.["human_oversight_uri"] !== "string" || constraints["human_oversight_uri"] === "") {
    errors.push("aiact.art26.deployer.human_oversight_uri_missing");
  }

  // scope.constraints.incident_reporting_uri
  if (typeof constraints?.["incident_reporting_uri"] !== "string" || constraints["incident_reporting_uri"] === "") {
    errors.push("aiact.art26.deployer.incident_reporting_uri_missing");
  }

  return { errors };
}

export const validateAiactArt26DeployerProfile = makeProfileAdapter(
  AIACT_ART26_DEPLOYER_PROFILE_ID,
  (body) => validateAiactArt26Deployer(body as AdrBody),
);
