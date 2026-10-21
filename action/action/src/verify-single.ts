/**
 * AActR body verifier (spec §4).
 *
 * Validates the single AActR body shape: plaintext action metadata
 * (`verb`/`rule_id`/`recipe_id`/`outcome`/`executed_at`) plus the three salted
 * `sha256` target commits. AActR is single-shape — there is no `event_type`
 * discriminator.
 *
 * SCOPE — shape only, NOT an authorization check. This validates that a single
 * receipt is well-formed and that `caveats_consumed`/`credential_id` are
 * present and correctly typed. It does NOT — and a stateless single-receipt
 * verifier CANNOT — check that the referenced mandate exists, is unrevoked,
 * actually granted the claimed `capability`/`data_scope`, or that a given
 * `spend_step` has not been replayed across receipts. Those are stateful
 * obligations of the issuing/consuming gateway (which runs mandate trust-bind,
 * scope, revocation, and a replay store BEFORE minting/executing). Never treat
 * a `valid: true` here as proof that an action was authorized.
 */

import type {
  AActRBody,
  AActROutcome,
  AActRProfile,
  AActRCaveatsConsumed,
  AActRDelegationChain,
  AActRArt12,
} from "./types.ts";
import type { AActRNonRevocationProof } from "@dekimuhq/action-profiles";

const RFC3339_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export interface VerifyBodyResult {
  valid: boolean;
  errors: string[];
  body: AActRBody | null;
}

const PROFILES = new Set<string>(["hub.automation", "aiact.art12"]);
const OUTCOMES = new Set<string>(["executed", "failed-gave-up"]);
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

export function verifyActionBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  if (!isProfile(b.profile)) errors.push("profile.invalid");
  if (!isNonEmptyString(b.verb)) errors.push("verb.missing");
  if (!isNonEmptyString(b.rule_id)) errors.push("rule_id.missing");
  if (!isNonEmptyString(b.recipe_id)) errors.push("recipe_id.missing");
  if (!isOutcome(b.outcome)) errors.push("outcome.invalid");
  if (!isNonEmptyString(b.executed_at)) errors.push("executed_at.missing");

  if (!isSha256Commit(b.decision_commit))
    errors.push("decision_commit.invalid");
  if (!isSha256Commit(b.params_commit)) errors.push("params_commit.invalid");
  if (!isSha256Commit(b.request_id_commit))
    errors.push("request_id_commit.invalid");

  // Mandate binding (spec §4.4 — additive, optional).
  if (b.credential_id !== undefined && !isNonEmptyString(b.credential_id))
    errors.push("credential_id.invalid");
  if (b.caveats_consumed !== undefined && !isCaveatsConsumed(b.caveats_consumed))
    errors.push("caveats_consumed.invalid");
  // Binding integrity: caveats are meaningless without the credential they bound.
  if (b.caveats_consumed !== undefined && b.credential_id === undefined)
    errors.push("caveats_consumed.orphan");

  // Delegation chain (spec §4.5 — additive, optional).
  if (b.delegation_chain !== undefined && !isDelegationChain(b.delegation_chain))
    errors.push("delegation_chain.invalid");
  // Binding integrity: a delegation path is meaningless without the credential it roots at.
  if (b.delegation_chain !== undefined && b.credential_id === undefined)
    errors.push("delegation_chain.orphan");
  // Binding integrity: the recorded chain root MUST be the bound credential, never a different one.
  if (
    isDelegationChain(b.delegation_chain) &&
    isNonEmptyString(b.credential_id) &&
    b.delegation_chain.root_credential_id !== b.credential_id
  )
    errors.push("delegation_chain.root_mismatch");
  // Binding integrity: a delegated action that records its path MUST also record the
  // authority slice it spent — a delegation with no consumed authority is incoherent.
  if (b.delegation_chain !== undefined && b.caveats_consumed === undefined)
    errors.push("delegation_chain.no_caveats");

  // Per-agent principal (spec §4.6 — additive, optional).
  if (b.agent_id !== undefined && !isNonEmptyString(b.agent_id))
    errors.push("agent_id.invalid");
  // Binding integrity: a verified per-agent principal only exists under a mandate —
  // an agent_id without the credential it was bound to is structurally meaningless.
  if (b.agent_id !== undefined && b.credential_id === undefined)
    errors.push("agent_id.orphan");

  // AI Act Article 12 overlay (spec §4.7 — additive, optional). Base verifier
  // shape-checks the field structure only; the `aiact.art12` PROFILE validator
  // enforces the regulatory semantics (RFC-3339 / enum / commit regex / presence).
  if (b.aiact_art12 !== undefined && !isAiactArt12(b.aiact_art12))
    errors.push("aiact_art12.invalid");

  // Stapled non-revocation proof (A4 — additive, optional). Shape-only: the
  // signature is verified by the runtime verifier (verifyNonRevocationProof),
  // never here. The body validator checks the proof's STRUCTURE and the
  // credential-binding invariant.
  if (b.non_revocation_proof !== undefined) {
    const p = b.non_revocation_proof;
    if (typeof p !== "object" || p === null) {
      errors.push("non_revocation_proof.invalid");
    } else {
      const np = p as Record<string, unknown>;
      // Shape: status, credential_id, status_list_ref, sig (sig is shape-only —
      // the cryptographic check is the runtime verifier's job, not here).
      if (!isNonRevocationProofShape(np))
        errors.push("non_revocation_proof.invalid");
      // `as_of` is a strict RFC-3339 timestamp; distinct code so a bad timestamp
      // is legible separately from a generic shape failure.
      if (!isRfc3339(np.as_of)) errors.push("non_revocation_proof.as_of_invalid");
    }
    // Binding integrity: a non-revocation proof is meaningless without the
    // credential it attests is unrevoked.
    if (b.credential_id === undefined) {
      errors.push("non_revocation_proof.orphan");
    } else if (
      isNonRevocationProofShape(b.non_revocation_proof) &&
      isNonEmptyString(b.credential_id) &&
      b.non_revocation_proof.credential_id !== b.credential_id
    ) {
      errors.push("non_revocation_proof.credential_mismatch");
    }
    // Receipt binding: the proof's `receipt_commit` MUST equal the body's
    // `request_id_commit` — this binds the proof to one specific action so it
    // cannot be lifted onto another receipt (request_id_commit is a required
    // body field, so it is always present when the body is otherwise valid).
    if (
      isNonRevocationProofShape(b.non_revocation_proof) &&
      isSha256Commit(b.request_id_commit) &&
      b.non_revocation_proof.receipt_commit !== b.request_id_commit
    ) {
      errors.push("non_revocation_proof.receipt_mismatch");
    }
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AActRBody };
}

function isProfile(v: unknown): v is AActRProfile {
  return typeof v === "string" && PROFILES.has(v);
}
function isOutcome(v: unknown): v is AActROutcome {
  return typeof v === "string" && OUTCOMES.has(v);
}
function isSha256Commit(v: unknown): v is string {
  return typeof v === "string" && SHA256_HEX_RE.test(v);
}
function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}
function isCaveatsConsumed(v: unknown): v is AActRCaveatsConsumed {
  if (typeof v !== "object" || v === null) return false;
  const c = v as Record<string, unknown>;
  return (
    isNonEmptyString(c.data_scope) &&
    typeof c.spend_step === "number" &&
    Number.isFinite(c.spend_step) &&
    // A decrement is non-negative in any unit (€ amount or call count); a negative
    // step is structurally meaningless — reject it (closes a misleading "-1" render).
    c.spend_step >= 0 &&
    // `spend_currency` is optional+additive; when present it must be a non-empty
    // string (the unit tag for a monetary `spend_step`). Stateless: this does NOT
    // check the currency against the granted budget — that's a stateful grant check,
    // out of scope here like `capability`/`data_scope` grant-matching above.
    (c.spend_currency === undefined || isNonEmptyString(c.spend_currency)) &&
    isNonEmptyString(c.capability)
  );
}
function isAiactArt12(v: unknown): v is AActRArt12 {
  if (typeof v !== "object" || v === null) return false;
  const a = v as Record<string, unknown>;
  return (
    // Required within the profile — the lifetime anchor, version, and start of use.
    isNonEmptyString(a.system_id) &&
    isNonEmptyString(a.system_version) &&
    isNonEmptyString(a.period_start) &&
    // Optional fields, when present, are non-empty strings. Deeper semantics
    // (RFC-3339 / risk_event enum / sha256 oversight_ref) are the profile validator's job.
    (a.period_end === undefined || isNonEmptyString(a.period_end)) &&
    (a.risk_event === undefined || isNonEmptyString(a.risk_event)) &&
    (a.oversight_ref === undefined || isNonEmptyString(a.oversight_ref))
  );
}
function isRfc3339(v: unknown): v is string {
  return typeof v === "string" && RFC3339_RE.test(v) && !Number.isNaN(Date.parse(v));
}
/**
 * Shape guard for the stapled non-revocation proof (everything EXCEPT `as_of`,
 * which gets its own distinct error code). Shape-only: `sig` is checked for
 * non-emptiness, NOT verified — the cryptographic check is the runtime
 * verifier's job (`verifyNonRevocationProof` in @dekimuhq/action-profiles).
 */
function isNonRevocationProofShape(v: unknown): v is AActRNonRevocationProof {
  if (typeof v !== "object" || v === null) return false;
  const n = v as Record<string, unknown>;
  return (
    n.status === "active" &&
    isNonEmptyString(n.credential_id) &&
    isNonEmptyString(n.status_list_ref) &&
    isNonEmptyString(n.receipt_commit) &&
    isNonEmptyString(n.sig)
  );
}
function isDelegationChain(v: unknown): v is AActRDelegationChain {
  if (typeof v !== "object" || v === null) return false;
  const d = v as Record<string, unknown>;
  return (
    // depth counts delegation hops beyond the root — a present chain delegated ≥1 time.
    typeof d.depth === "number" &&
    Number.isInteger(d.depth) &&
    d.depth >= 1 &&
    isNonEmptyString(d.leaf_key) &&
    isNonEmptyString(d.root_credential_id)
  );
}
