/**
 * `gdpr.dsr.authorised-agent` profile validator — ADR spec section 5.
 *
 * Hook: an **authorised representative** exercising a data subject's GDPR
 * data-subject rights against a single named controller. This models the
 * general "authorised agent / representative" acceptance route — a national
 * civil-law mandate / power of attorney granted by the subject, backed by
 * GDPR Art. 12(2) (controller shall facilitate), Art. 12(6) (identity check),
 * and Recital 59 (requests made by others on the subject's behalf).
 *
 * It is deliberately NOT `gdpr.art80.*`: GDPR Art. 80(1)/(2) is a mandate to a
 * **not-for-profit** body with statutory data-protection objectives and does
 * not apply to a commercial representative. It is also NOT
 * `gdpr.art28.processor`: the representative acts *for the subject*, not as a
 * processor of the controller.
 *
 * Because the representative is a legal/natural person (not an autonomous AI
 * agent), the delegation's `agent` is identity-shaped — a verification key with
 * no AI `agent_descriptor` — distinguishing it from the AI-agent profiles
 * (`aiact.art26.deployer` REQUIRES a descriptor).
 *
 * v1 invariants enforced here (grant events only):
 *   - `body.delegable` MUST be `false` — a subject mandate is non-sub-delegable.
 *   - `body.agent.agent_descriptor` MUST be `null` — a representative is not an
 *     autonomous AI agent (contrast `aiact.art26.deployer`).
 *   - `body.agent.agent_pubkey` MUST be a non-empty string — the representative's
 *     verification key.
 *   - `body.scope.actions` MUST be a non-empty array of exercisable DSR article
 *     ids, each ⊆ {gdpr-art-15, -16, -17, -18, -20, -21}.
 *   - `body.scope.resources` MUST name exactly one controller (a single
 *     non-empty string) — authority is per-controller, non-transferable.
 *   - `body.scope.constraints.letter_hash` MUST be `sha256:<64-hex>` — binds the
 *     human-readable Letter of Authority (Layer 1) to this credential (Layer 2).
 *   - `body.scope.constraints.representative` MUST be a non-empty string naming
 *     the representative legal person (e.g. its registered company name).
 *   - `body.scope.constraints.mandate_basis` MUST be a non-empty string stating
 *     the legal basis of the mandate (governing law + GDPR articles invoked).
 */

import type { AdrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_DSR_AUTHORISED_AGENT_PROFILE_ID =
  "gdpr.dsr.authorised-agent" as const;

/** `sha256:` followed by exactly 64 lowercase hex chars. */
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;

/** Data-subject rights a representative may be mandated to exercise. */
const EXERCISABLE_DSR_ACTIONS = new Set([
  "gdpr-art-15", // access
  "gdpr-art-16", // rectification
  "gdpr-art-17", // erasure
  "gdpr-art-18", // restriction
  "gdpr-art-20", // portability
  "gdpr-art-21", // objection
]);

export function validateGdprDsrAuthorisedAgent(
  body: AdrBody,
): ProfileValidationResult {
  const errors: string[] = [];
  if (body.event !== "grant") return { errors };

  const b = body as unknown as Record<string, unknown>;

  // A subject mandate is never sub-delegable.
  if (b["delegable"] !== false) {
    errors.push("gdpr.dsr.authorised-agent.delegable_must_be_false");
  }

  // The representative is a legal person, not an autonomous AI agent.
  const agent = b["agent"] as Record<string, unknown> | undefined;
  if (agent?.["agent_descriptor"] !== null) {
    errors.push("gdpr.dsr.authorised-agent.agent_descriptor_must_be_null");
  }
  if (typeof agent?.["agent_pubkey"] !== "string" || agent["agent_pubkey"] === "") {
    errors.push("gdpr.dsr.authorised-agent.agent_pubkey_missing");
  }

  const scope = b["scope"] as Record<string, unknown> | undefined;

  // actions: non-empty, each an exercisable DSR article id.
  const actions = scope?.["actions"];
  if (
    !Array.isArray(actions) ||
    actions.length === 0 ||
    !actions.every(
      (a) => typeof a === "string" && EXERCISABLE_DSR_ACTIONS.has(a),
    )
  ) {
    errors.push("gdpr.dsr.authorised-agent.actions_invalid");
  }

  // resources: exactly one named controller (per-controller, non-transferable).
  const resources = scope?.["resources"];
  if (
    !Array.isArray(resources) ||
    resources.length !== 1 ||
    typeof resources[0] !== "string" ||
    resources[0] === ""
  ) {
    errors.push(
      "gdpr.dsr.authorised-agent.resources_must_name_single_controller",
    );
  }

  const constraints = scope?.["constraints"] as
    | Record<string, unknown>
    | undefined;

  // letter_hash binds Layer 1 (the human-readable letter) to Layer 2.
  const letterHash = constraints?.["letter_hash"];
  if (typeof letterHash !== "string" || !SHA256_RE.test(letterHash)) {
    errors.push("gdpr.dsr.authorised-agent.letter_hash_invalid");
  }

  // representative: the named legal person holding the authority.
  if (
    typeof constraints?.["representative"] !== "string" ||
    constraints["representative"] === ""
  ) {
    errors.push("gdpr.dsr.authorised-agent.representative_missing");
  }

  // mandate_basis: the stated legal grounding of the mandate.
  if (
    typeof constraints?.["mandate_basis"] !== "string" ||
    constraints["mandate_basis"] === ""
  ) {
    errors.push("gdpr.dsr.authorised-agent.mandate_basis_missing");
  }

  return { errors };
}

export const validateGdprDsrAuthorisedAgentProfile = makeProfileAdapter(
  GDPR_DSR_AUTHORISED_AGENT_PROFILE_ID,
  (body) => validateGdprDsrAuthorisedAgent(body as AdrBody),
);
