/**
 * AActR (Anchored Action Receipts) body-type definitions.
 *
 * Body shape — what goes in `Envelope.body` — plus the profile-id union the
 * profile validators are keyed by.
 *
 * These types live in `@dekimuhq/action-profiles` (not the verifier) so the
 * profile validators can import the body shape without depending on the
 * verifier package — the verifier imports profile *values* (`family.ts`), so a
 * profiles→verifier type edge would form an import cycle that blocks the
 * topological built-`dist` publish. `@dekimuhq/action` re-exports every symbol
 * here, so its public API is unchanged for downstream consumers.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`, `prev`,
 * `credentialStatus`, `tsa`, `anchor`, `sig`, `countersig`, `kind`, `cause`,
 * `predicate`) are provided by `@dekimuhq/anchors-envelope` and are NOT repeated
 * here. `field_root` is added issuer-side by `mintActionV2` and is not part of
 * the canonical body input shape.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/action.
 */

import type { AActRNonRevocationProof } from "./non-revocation.ts";

// ── Claim type ────────────────────────────────────────────────────────────────

export type AActRClaimType = "ar.action.v1";

// ── Profiles (spec §5) ──────────────────────────────────────────────────────────

/**
 * AActR profiles (exclusive — selected by `body.profile`, like ACR's
 * `gdpr.art7` / `aiact.art14`):
 *  - `hub.automation` — the Dekimu Hub automations engine action record (v1 default issuer).
 *  - `aiact.art12`    — an EU AI Act Article 12 record-keeping log entry: the SAME
 *    Hub-automation action, declared as a high-risk-system log event and carrying the
 *    `aiact_art12` field. See https://github.com/dekimuhq/anchors-spec/blob/main/action/aiact-art12-mapping.md.
 */
export type AActRProfile = "hub.automation" | "aiact.art12";

// ── EU AI Act Article 12 record-keeping overlay (spec §4.7 — additive, optional) ─

/** Art.12(2)(a) risk-relevant event class. `none` = ordinary logged use. */
export type AActRArt12RiskEvent =
  | "none"
  | "risk_flagged"
  | "substantial_modification";

/**
 * EU AI Act Article 12 (record-keeping) logical fields, carried when the action
 * is logged as a high-risk-AI-system event (`profile: "aiact.art12"`).
 *
 * Additive optional body object (same shape-additive pattern as `caveats_consumed`
 * / `delegation_chain` — existing receipts verify byte-equal; absent ⇒ omitted from
 * the canonical body, RFC 8785). Encoded as a nested object rather than the
 * pipe-pack used by ACR's `aiact.art14` because AActR already carries nested
 * optional objects natively — there is no reused legacy field to pack into here.
 *
 * `system_id` / `system_version` / `period_start` are REQUIRED **within this
 * profile** (the conformance assertion): if a receipt claims `aiact.art12` it
 * asserts the lifetime anchor (`system_id`), the version that produced the event
 * (`system_version` — a change is the Art.12(2)(a) "substantial modification"
 * signal), and the start of use (Art.12(3)(a)). The remainder are optional.
 *
 * Honesty boundary: this is the **record-keeping primitive** that helps satisfy
 * Art. 12 + Art. 19, NOT "Article 12 compliance" — conformity assessment, risk
 * management (Art. 9), data governance (Art. 10) are out of scope.
 */
export interface AActRArt12 {
  /** Stable id of the high-risk AI system over its lifetime (Art.12(1)). The log-set export filter key. */
  system_id: string;
  /** Released system version producing this event; a change ⇒ Art.12(2)(a) "substantial modification" signal. */
  system_version: string;
  /** Art.12(3)(a) start of use. RFC 3339 / ISO 8601 UTC. */
  period_start: string;
  /** OPTIONAL. Art.12(3)(a) end of use. RFC 3339 / ISO 8601 UTC. May arrive in a later amendment receipt. */
  period_end?: string;
  /** OPTIONAL. Art.12(2)(a) risk-relevant event class. Absent ⇒ treated as `none`. */
  risk_event?: AActRArt12RiskEvent;
  /**
   * OPTIONAL. Art.12(3)(d) / Art.14(5): `sha256:<hex>` pointing to the `aiact.art14`
   * oversight receipt that identifies the natural person(s) who verified the result.
   */
  oversight_ref?: string;
}

// ── Outcome (spec §4.1) ─────────────────────────────────────────────────────────

/**
 * The terminal outcome of the action.
 *  - `executed`        — the dispatched verb ran and the engine accepted the result.
 *  - `failed-gave-up`  — the engine attempted the verb, exhausted retries, and stopped.
 *
 * Both outcomes mint a receipt (spec §11.3): "the machine tried and stopped" is
 * as audit-worthy as a success.
 */
export type AActROutcome = "executed" | "failed-gave-up";

// ── Mandate binding (spec §4.4 — additive, optional) ──────────────────────────

/**
 * The attenuated authority a single action actually exercised. Plaintext,
 * non-PII bounds (NOT the data itself — any PII target stays in `params_commit`).
 * Present only when the action ran under a capability mandate (the gated door);
 * absent for policy-authorized auto actions.
 */
export interface AActRCaveatsConsumed {
  /** The data-scope bound exercised (workspace id or a narrower non-PII selector). */
  data_scope: string;
  /**
   * Budget this one action decremented from the mandate. Unit is governed by
   * `spend_currency`:
   *  - `spend_currency` PRESENT → `spend_step` is an amount in that ISO-4217
   *    currency, provably within the credential's granted `spendMax` (the issuer
   *    records it ONLY when a verified spend-budget caveat bounds the call).
   *  - `spend_currency` ABSENT → `spend_step` is call-count units (default `1` =
   *    one reversible action); no money meaning.
   * A consumer MUST NOT read `spend_step` as money unless `spend_currency` is set.
   */
  spend_step: number;
  /**
   * OPTIONAL (additive). ISO-4217 currency code denominating `spend_step` when the
   * decrement is a budget-bound monetary amount. Present iff the action ran under a
   * mandate carrying a satisfied `spendBudget` caveat whose currency this matches.
   * Absent → `spend_step` is a call-count unit, not money.
   */
  spend_currency?: string;
  /** The capability/verb invoked (e.g. `ropa.compile`, `invoiceup.remind`). */
  capability: string;
}

// ── Delegation chain (spec §4.5 — additive, optional) ─────────────────────────

/**
 * The delegation path of the authorizing mandate, recorded when an action ran
 * under a DELEGATED sub-mandate (a sub-agent acting via `attenuate`) rather than
 * the root principal's own mandate. Lets a verifier see "this action was taken
 * by a sub-agent at chain depth N, rooted at credential X" — beyond the single
 * root `credential_id`. Plaintext, non-PII metadata; the chain already lives,
 * signed, in the capability token, so this introduces NO new cryptographic
 * primitive (the verify-time caveat-intersection boundary is unchanged).
 */
export interface AActRDelegationChain {
  /**
   * Number of delegation hops beyond the root mandate block. Always `>= 1` when
   * present (a root-only mandate omits `delegation_chain` entirely).
   */
  depth: number;
  /**
   * base64url delegation key (`nextKey`) of the chain's leaf block — a stable,
   * signed identifier of the leaf delegate's chain position.
   */
  leaf_key: string;
  /**
   * The root mandate's credential id. MUST equal the body's `credential_id`
   * (the root is the same credential whether or not it delegated onward); the
   * reference verifier rejects a mismatch (`delegation_chain.root_mismatch`).
   */
  root_credential_id: string;
}

// ── Body (spec §4.1) ─────────────────────────────────────────────────────────────

/**
 * Canonical AActR body. Null-subject, workspace/activity-level: the action's
 * *target* lives here as salted commits, never as the envelope `subject`.
 *
 * Plaintext fields (`verb`/`rule_id`/`recipe_id`/`outcome`/`executed_at`) are
 * non-PII and legible: an audit receipt is useless if the owner cannot read what
 * the machine did. The three `*_commit` fields are salted `sha256` commits
 * (`commit(salt, canonicalize(value))`) because `params` may carry PII (e.g. a
 * debtor email) and decision/params are low-entropy — committing keeps the
 * publicly-anchored receipt GDPR-clean while still binding the exact target.
 */
export interface AActRBody {
  /** Issuing profile: `"hub.automation"` (default) or `"aiact.art12"` (AI Act Art.12 log entry). */
  profile: AActRProfile;
  /** The dispatched verb, `<ns>.<op>` (e.g. `invoiceup.remind`). Plaintext, non-PII. */
  verb: string;
  /** The owner-enabled rule that authorized automation. Plaintext, non-PII. */
  rule_id: string;
  /** The catalog recipe the rule instantiates. Plaintext, non-PII. */
  recipe_id: string;
  /** Terminal outcome. */
  outcome: AActROutcome;
  /** RFC 3339 / ISO 8601 UTC timestamp the action executed. */
  executed_at: string;
  /** `sha256:<hex>` — `commit(salt, canonicalize(decisionId))`. */
  decision_commit: string;
  /** `sha256:<hex>` — `commit(salt, canonicalize(params))`. */
  params_commit: string;
  /** `sha256:<hex>` — `commit(salt, canonicalize(`${ruleId}:${decisionId}`))` (idempotency key). */
  request_id_commit: string;
  /**
   * OPTIONAL (additive, spec §4.4). The authorizing mandate's credential id —
   * the gateway `AgentCredentialEnvelope.credentialId` (= ADR grant claimId).
   * Plaintext + revocation-checkable. **Absent** for policy-authorized actions
   * (the Operator auto path has no mandate).
   */
  credential_id?: string;
  /**
   * OPTIONAL (additive, spec §4.4). The slice of the mandate's authority spent
   * by this action. Present iff `credential_id` is present.
   */
  caveats_consumed?: AActRCaveatsConsumed;
  /**
   * OPTIONAL (additive, spec §4.5). The delegation path when the authorizing
   * mandate is a CHAIN (a sub-agent acting under an attenuated sub-mandate).
   * Present iff `credential_id` AND `caveats_consumed` are present AND the
   * mandate delegated at least once; `root_credential_id` MUST equal
   * `credential_id`. Root-only mandates omit it.
   */
  delegation_chain?: AActRDelegationChain;
  /**
   * OPTIONAL (additive, spec §4.7). EU AI Act Article 12 record-keeping overlay.
   * Present iff `profile === "aiact.art12"` (the `aiact.art12` profile validator
   * requires it; the `hub.automation` profile does not carry it). Carries the
   * high-risk-system log fields (`system_id`, `period_start`, …). Plaintext,
   * non-PII metadata; the action target itself stays in the `*_commit` fields.
   */
  aiact_art12?: AActRArt12;
  /**
   * OPTIONAL (additive, spec §4.6). The stable per-AGENT principal that took this
   * action — the `agentId` cryptographically bound into the authorizing mandate's
   * ROOT block and surfaced by `@dekimuhq/mandate-verify` as `verdict.verifiedAgentId`
   * (only on a fully-valid, root-bound, non-contradicted verdict). Distinct from
   * `credential_id` (per-MANDATE) and the envelope `iss` (per-TENANT): it answers
   * "WHICH agent", stable across that agent's many mandates. Present iff
   * `credential_id` is present (no mandate ⇒ no verified principal) AND the mandate
   * carried an agentId — a mandate-bound action whose mandate omits agentId still
   * mints, just without this field. Plaintext, non-PII (an opaque principal id, not
   * the data acted on). Closes the AIUC-1 A003.3 identity-granularity gap on the
   * receipt side. The issuer MUST populate it only from a verified mandate; a
   * stateless single-receipt verifier cannot re-derive it (it lives in the mandate
   * chain, not the receipt) — the same issuer-asserted boundary as `credential_id`.
   */
  agent_id?: string;
  /**
   * Stapled proof the authorizing mandate was not revoked at action time
   * (A4). Optional + additive: receipts without it stay valid. Present only
   * when `credential_id` is present. `non_revocation_proof.credential_id`
   * MUST equal `credential_id`. Verified offline against the issuer key.
   */
  non_revocation_proof?: AActRNonRevocationProof;
}
