/**
 * `agentops.scoped-delegation` profile validator — ADR spec section 5.
 *
 * Generic vendor-neutral delegation profile. Lightweight — no extra validation
 * beyond what the body schema already enforces for scope/agent/delegable.
 * Always returns `{ errors: [] }`.
 */

import type { AdrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AGENTOPS_SCOPED_DELEGATION_PROFILE_ID = "agentops.scoped-delegation" as const;

export function validateAgentopsScopedDelegation(_body: AdrBody): ProfileValidationResult {
  return { errors: [] };
}

export const validateAgentopsScopedDelegationProfile = makeProfileAdapter(
  AGENTOPS_SCOPED_DELEGATION_PROFILE_ID,
  (body) => validateAgentopsScopedDelegation(body as AdrBody),
);
