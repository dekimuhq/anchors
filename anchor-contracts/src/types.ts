/**
 * Public types for @dekimuhq/anchor-contracts (P0).
 *
 * A contract is a PLAIN object (no wire member in P0). It references the
 * envelope's shipped JSON Logic predicate type for field constraints.
 */
import type { Envelope, ClaimType, JsonLogicAst } from "@dekimuhq/anchors-envelope";

/**
 * The verdict a family verifier already produced for an anchor. P0 trusts this
 * (it does NOT re-verify) and refuses to fire on a falsy/revoked anchor.
 * Structural subset of the envelope's `FamilyVerifyResult`.
 */
export interface AnchorVerdict {
  /** From the family verifier. P0 refuses any anchor where this is not `true`. */
  signature_valid: boolean;
  /**
   * Status result from the family verifier (`StatusCheck["state"]` /
   * `SuspensionCheck["state"]`). The trust gate is deny-by-default: a present
   * value outside `ACCEPTABLE_STATUS_STATES` (revoked*, suspended*, unreachable,
   * invalid_pointer, list_*) refuses. `undefined` = caller supplied no status
   * (opted out of revocation checking) and is allowed.
   */
  status_state?: string;
  /** Optional surfaced claim_type (informational). */
  claim_type?: string;
}

/** An anchor paired with the verdict from its family verifier. */
export interface VerifiedAnchor {
  envelope: Envelope;
  verdict: AnchorVerdict;
}

/** Inclusive ISO 8601 time window on `envelope.iat`. */
export interface TimeWindow {
  /** Lower bound (inclusive). ISO 8601. */
  fromIat?: string;
  /** Upper bound (inclusive). ISO 8601. */
  toIat?: string;
}

/** One precondition — matches exactly one anchor from the pool. */
export interface Precondition {
  /** Context key for the matched envelope (defaults to the precondition index as a string). */
  as?: string;
  /** Required discriminator. */
  claimType: ClaimType;
  /** Allowed issuers (`envelope.iss`). Omitted/empty = any issuer (discouraged). */
  issuers?: string[];
  /** Exact `envelope.subject` match. */
  subjectEquals?: string;
  /** Reject revoked anchors. Default `true`. */
  notRevoked?: boolean;
  /** Inclusive time window on `envelope.iat`. */
  within?: TimeWindow;
  /** Extra field constraints, evaluated against the single matched envelope. */
  where?: JsonLogicAst;
}

/** A state edge. */
export interface Transition {
  from: string;
  to: string;
}

/** A declarative Anchor Contract (plain object; identified by content hash). */
export interface AnchorContract {
  /** Stable human id (not a wire id). */
  id: string;
  /** Semver of the rule. */
  version: string;
  /** All must match — one anchor each. */
  preconditions: Precondition[];
  /** The state edge this contract authorises. */
  transition: Transition;
  /** Optional predicate over the COMBINED matched context. Must evaluate to strict `true`. */
  where?: JsonLogicAst;
}

/** Why a precondition/contract refused to fire. */
export type RefusalReason =
  | "precondition_unmatched"
  | "anchor_signature_invalid"
  | "anchor_revoked"
  | "predicate_invalid_ast"
  | "predicate_evaluation_false"
  | "predicate_eval_error"
  | "wrong_from_state"
  | "unknown_contract";

/** Result of matching a single precondition against a single anchor. */
export type MatchResult =
  | { ok: true }
  | { ok: false; reason: RefusalReason; detail?: string };

/** Outcome of evaluating a contract against a pool. */
export interface TransitionVerdict {
  contractId: string;
  contractHash: string;
  from: string;
  to: string;
  fired: boolean;
  reason?: RefusalReason;
  detail?: string;
  /** Matched envelopes keyed by precondition label/index — present only when `fired`. */
  matched?: Record<string, Envelope>;
}

/** A machine: a set of states + the contracts that are its transition edges. */
export interface MachineDefinition {
  states: string[];
  initial: string;
  contracts: AnchorContract[];
}

/** Live machine state + ordered audit trail of FIRED transitions. */
export interface MachineState {
  current: string;
  trail: TransitionVerdict[];
}
