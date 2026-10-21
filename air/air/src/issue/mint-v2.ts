/**
 * AIR v=2 mint path — produces v=2 Envelopes for Anchored Impact-Assessment
 * Receipts (DPIA lifecycle).
 *
 * Single export surface: `mintAirV2(input)` with `event_type`-discriminated
 * input. AIR is v=2 only (no v=1 legacy). Per-event-type convenience wrappers
 * live in `mint-single.ts`.
 *
 * Per FAMILY-CONSISTENCY §3 + AIR §E + D10-AIR-6:
 *   - `dpia.stakeholders_consulted` MAY take an OPTIONAL `subject` input. If
 *     supplied, it MUST be `"sha256:<hex>"` AND `consultation_method` MUST be
 *     `"representative_org"` or `"ngo_review"`. Any other shape (raw string,
 *     subject + non-bearing method) is rejected at mint time so the receipt
 *     can never be issued in a state the verifier will reject.
 *   - every other event_type → envelope `subject` is hard-pinned `null`. The
 *     input interfaces for those events do not expose a `subject` parameter,
 *     so callers cannot accidentally diverge.
 *
 * Per AIR §D + FAMILY-CONSISTENCY §2:
 *   - `dpia.completed`, `dpia.prior_consultation_initiated`,
 *     `dpia.prior_consultation_resolved` → TSA RECOMMENDED (verifier upgrades
 *     `tsa_absent` to `tsa_recommended` warning when omitted).
 *   - every other event_type → TSA OPTIONAL.
 *   - AIR v1 has NO MANDATORY-TSA event. The kit does not block minting
 *     without TSA on any event.
 *
 * Per-event envelope `kind` defaults are set by `buildEnvelopeKind` to match
 * the spec's §3.1 table (observation vs decision). Callers can override via
 * `envelope_kind`. Pass `null` to opt out (v1.1-compat). The defaults are
 * the spec-correct values, so most call sites should leave the field unset.
 *
 * `field_root` is computed over the body fields and embedded inside the body
 * (`AirV2BodyOut`). The air-verifier types do not yet declare it; the verifier
 * ignores extra fields per its field-by-field check approach.
 *
 * Phase 5 §H of the 10-spec batch.
 */

import {
  signEnvelope,
  generateReceiptId,
  keyObjectFromSeed,
  computeFieldRoot,
  isSha256Hex,
  type Envelope,
  type AnchorProof,
  type Kind,
  type Cause,
  type JsonLogicAst,
} from "@dekimuhq/anchors-envelope";
import {
  TsaMintError,
  attachTsaBlock,
  type TsaFetcher,
  type TsaConfig,
} from "@dekimuhq/anchors-envelope/tsa";
import {
  attachCredentialStatus,
  type StatusListConfig,
  attachSuspensionStatus,
  type SuspensionListConfig,
} from "@dekimuhq/anchors-envelope/status";
import type {
  AirBody,
  AirEventType,
  AirThresholdTriggeredBody,
  AirScopeLockedBody,
  AirDpoAdvisedBody,
  AirStakeholdersConsultedBody,
  AirCompletedBody,
  AirReviewedBody,
  AirPriorConsultationInitiatedBody,
  AirPriorConsultationResolvedBody,
  AirProcessingAuthorisedBody,
  AirProcessingBlockedBody,
  AirTerminatedBody,
  AirProfile,
  AirConsultationMethod,
  AirResidualRiskLevel,
  AirReviewOutcome,
} from "../index.ts";

const AIR_CLAIM_TYPE = "ar.impact.v1" as const;

export type { StatusListConfig, SuspensionListConfig, TsaFetcher };
export { TsaMintError };

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

/**
 * Body emitted by the AIR v=2 mint surface. Identical to the verifier's
 * `AirBody` discriminated union with a `field_root` commitment appended.
 * Verifier ignores extra fields today; future verifier hardening will adopt
 * this shape directly.
 */
export type AirV2BodyOut = AirBody & { field_root: string };

// ── Input interfaces ──────────────────────────────────────────────────────────

interface MintAirV2Common {
  /** Issuer DID or short identifier (controller). */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** AIR regulatory profile (spec §5). */
  profile: AirProfile;
  /**
   * Stable identifier for the DPIA chain — every receipt in a DPIA lifecycle
   * MUST share this value (D10-AIR-2). §C chain walker enforces parity.
   */
  air_receipt_id: string;
  /**
   * Stable identifier for the processing activity covered by the DPIA. Two
   * DPIAs over the same processing activity share this id (D10-AIR-3); §6.4
   * chain re-DPIA lookup keys on it.
   */
  processing_activity_id: string;
  /** Envelope-level policy URI (POLICY_BOUND on ar.impact.v1). */
  policy_uri: string;
  /** SHA-256 hash of the rendered DPIA methodology document. */
  policy_hash: string;
  /** Semantic version of the DPIA methodology. */
  policy_version: string;
  /** Anchor proof (caller supplies; log worker replaces post-mint). */
  anchor: AnchorProof;
  /** Optional: previous receipt ID for chain linkage. */
  prev?: string | null;
  /** Optional: expiry ISO 8601 UTC. */
  exp?: string | null;
  /** Optional: TSA configuration. If present, tsaFetcher must also be provided. */
  tsa?: TsaConfig;
  /** Optional: TSA fetcher (caller-provided; required if `tsa` is set). */
  tsaFetcher?: TsaFetcher;
  /**
   * Optional: W3C Bitstring Status List 2021 pointer config. Attached BEFORE
   * signing per spec §6.3. AIR is status-list consumer position #6.
   */
  statusList?: StatusListConfig;
  /**
   * Optional: Suspension List configuration. When provided, a W3C Bitstring
   * Status List 2021 Entry pointer with statusPurpose "suspension" is minted
   * and embedded BEFORE signing. Suspension is two-way (suspend/unsuspend),
   * unlike revocation which is permanent.
   */
  suspensionList?: SuspensionListConfig;
  /**
   * v1.2 §4.1: receipt classification — observation vs decision. AIR defaults
   * per-event-type via `buildEnvelopeKind`. Pass `null` to opt out
   * (v1.1-compat); pass a `Kind` to override the per-event default.
   */
  envelope_kind?: Kind | null;
  /** v1.2 §4.2: typed trigger (closed enum). Optional. */
  cause?: Cause | null;
  /** v1.2 §4.3: optional JSON Logic predicate. Operators MUST be inside the v1.2 allowlist. */
  predicate?: JsonLogicAst | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintAirV2ThresholdTriggeredInput extends MintAirV2Common {
  event_type: "dpia.threshold_triggered";
  /** Stable canonical hash of the RoPA-entry snapshot in scope at trigger time. */
  processing_activity_hash: string;
  /** ISO 8601 UTC — when processing under this DPIA scope starts (or did start). */
  processing_start_at: string;
}

export interface MintAirV2ScopeLockedInput extends MintAirV2Common {
  event_type: "dpia.scope_locked";
  scope_hash: string;
}

export interface MintAirV2DpoAdvisedInput extends MintAirV2Common {
  event_type: "dpia.dpo_advised";
  dpo_did_or_email_commit: string;
  dpo_advice_hash: string;
}

export interface MintAirV2StakeholdersConsultedInput extends MintAirV2Common {
  event_type: "dpia.stakeholders_consulted";
  consultation_method: AirConsultationMethod;
  consultation_output_hash: string;
  /**
   * OPTIONAL representative-org / NGO-review `sub_commit` (D10-AIR-6). MUST be
   * `"sha256:<64-hex>"` if present, AND `consultation_method` MUST be
   * `"representative_org"` or `"ngo_review"`. Any other shape rejects at mint
   * time. Omit (or pass `null`) on all other consultation methods.
   */
  subject?: string | null;
}

export interface MintAirV2CompletedInput extends MintAirV2Common {
  event_type: "dpia.completed";
  dpia_artifact_hash: string;
  dpia_uri: string;
  residual_risk_level: AirResidualRiskLevel;
  /** ISO 8601 UTC — next scheduled review per Art. 35(11). */
  review_due_at: string;
  /** Composition: AER (ar.evaluation.v1) receipt ids (§8.1). */
  aer_receipt_ids?: readonly string[] | null;
  /** Composition: ATR (ar.transfer.v1) receipt ids for cross-border transfers (§8.2). */
  atr_receipt_ids?: readonly string[] | null;
  /** Composition: ALR (ar.lineage.v1) receipt ids for data flows in scope (§8.3). */
  alr_receipt_ids?: readonly string[] | null;
  /** Composition: APuR (ar.purpose.v1) receipt ids for purpose bindings (§8.4). */
  apur_receipt_ids?: readonly string[] | null;
}

export interface MintAirV2ReviewedInput extends MintAirV2Common {
  event_type: "dpia.reviewed";
  review_outcome: AirReviewOutcome;
  review_evidence_hash: string;
  /** Composition: ABR (ar.breach.v1) receipt id when review is breach-triggered (§8.5). */
  abr_receipt_id?: string | null;
}

export interface MintAirV2PriorConsultationInitiatedInput extends MintAirV2Common {
  event_type: "dpia.prior_consultation_initiated";
  /** ISO 3166-1 alpha-2 (e.g. "ES", "DE") or the literal "EU-EDPB". */
  dpa_jurisdiction: string;
  submission_hash: string;
}

export interface MintAirV2PriorConsultationResolvedInput extends MintAirV2Common {
  event_type: "dpia.prior_consultation_resolved";
  dpa_advice_hash: string;
  controller_response_hash: string;
  /** OPTIONAL DPA DID; `null` when DPA hasn't signed (pre-EUDI-Wallet rare). */
  dpa_did?: string | null;
}

export interface MintAirV2ProcessingAuthorisedInput extends MintAirV2Common {
  event_type: "dpia.processing_authorised";
}

export interface MintAirV2ProcessingBlockedInput extends MintAirV2Common {
  event_type: "dpia.processing_blocked";
}

export interface MintAirV2TerminatedInput extends MintAirV2Common {
  event_type: "dpia.terminated";
  termination_reason_hash: string;
}

export type MintAirV2Input =
  | MintAirV2ThresholdTriggeredInput
  | MintAirV2ScopeLockedInput
  | MintAirV2DpoAdvisedInput
  | MintAirV2StakeholdersConsultedInput
  | MintAirV2CompletedInput
  | MintAirV2ReviewedInput
  | MintAirV2PriorConsultationInitiatedInput
  | MintAirV2PriorConsultationResolvedInput
  | MintAirV2ProcessingAuthorisedInput
  | MintAirV2ProcessingBlockedInput
  | MintAirV2TerminatedInput;

// ── Internal helpers ──────────────────────────────────────────────────────────

const SUBJECT_BEARING_METHODS: ReadonlySet<AirConsultationMethod> = new Set([
  "representative_org",
  "ngo_review",
]);

const ISO_ALPHA2 = /^[A-Z]{2}$/;

function isAirJurisdiction(s: string): boolean {
  return s === "EU-EDPB" || ISO_ALPHA2.test(s);
}

/**
 * Per-event default envelope `kind` per spec §3.1. Callers can override via
 * the `envelope_kind` input.
 */
function buildEnvelopeKind(event_type: AirEventType): Kind {
  if (
    event_type === "dpia.threshold_triggered" ||
    event_type === "dpia.dpo_advised" ||
    event_type === "dpia.stakeholders_consulted" ||
    event_type === "dpia.prior_consultation_resolved"
  ) {
    return "observation";
  }
  return "decision";
}

function baseBodyCommon(input: MintAirV2Common): {
  air_receipt_id: string;
  processing_activity_id: string;
  qts_attestation_hash: string | null;
} {
  return {
    air_receipt_id: input.air_receipt_id,
    processing_activity_id: input.processing_activity_id,
    qts_attestation_hash: input.qts_attestation_hash ?? null,
  };
}

function buildBody(input: MintAirV2Input): AirBody {
  switch (input.event_type) {
    case "dpia.threshold_triggered": {
      const body: AirThresholdTriggeredBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.threshold_triggered",
        processing_activity_hash: input.processing_activity_hash,
        processing_start_at: input.processing_start_at,
        scope_hash: null,
        dpo_did_or_email_commit: null,
        dpo_advice_hash: null,
        consultation_method: null,
        consultation_output_hash: null,
        dpia_artifact_hash: null,
        dpia_uri: null,
        residual_risk_level: null,
        review_due_at: null,
        review_outcome: null,
        review_evidence_hash: null,
        dpa_jurisdiction: null,
        submission_hash: null,
        dpa_advice_hash: null,
        dpa_did: null,
        controller_response_hash: null,
        terminal_disposition: null,
        termination_reason_hash: null,
        aer_receipt_ids: null,
        atr_receipt_ids: null,
        alr_receipt_ids: null,
        apur_receipt_ids: null,
        abr_receipt_id: null,
      };
      return body;
    }
    case "dpia.scope_locked": {
      const body: AirScopeLockedBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.scope_locked",
        scope_hash: input.scope_hash,
        processing_activity_hash: null,
        processing_start_at: null,
        dpo_did_or_email_commit: null,
        dpo_advice_hash: null,
        consultation_method: null,
        consultation_output_hash: null,
        dpia_artifact_hash: null,
        dpia_uri: null,
        residual_risk_level: null,
        review_due_at: null,
        review_outcome: null,
        review_evidence_hash: null,
        dpa_jurisdiction: null,
        submission_hash: null,
        dpa_advice_hash: null,
        dpa_did: null,
        controller_response_hash: null,
        terminal_disposition: null,
        termination_reason_hash: null,
        aer_receipt_ids: null,
        atr_receipt_ids: null,
        alr_receipt_ids: null,
        apur_receipt_ids: null,
        abr_receipt_id: null,
      };
      return body;
    }
    case "dpia.dpo_advised": {
      const body: AirDpoAdvisedBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.dpo_advised",
        dpo_did_or_email_commit: input.dpo_did_or_email_commit,
        dpo_advice_hash: input.dpo_advice_hash,
        processing_activity_hash: null,
        processing_start_at: null,
        scope_hash: null,
        consultation_method: null,
        consultation_output_hash: null,
        dpia_artifact_hash: null,
        dpia_uri: null,
        residual_risk_level: null,
        review_due_at: null,
        review_outcome: null,
        review_evidence_hash: null,
        dpa_jurisdiction: null,
        submission_hash: null,
        dpa_advice_hash: null,
        dpa_did: null,
        controller_response_hash: null,
        terminal_disposition: null,
        termination_reason_hash: null,
        aer_receipt_ids: null,
        atr_receipt_ids: null,
        alr_receipt_ids: null,
        apur_receipt_ids: null,
        abr_receipt_id: null,
      };
      return body;
    }
    case "dpia.stakeholders_consulted": {
      const body: AirStakeholdersConsultedBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.stakeholders_consulted",
        consultation_method: input.consultation_method,
        consultation_output_hash: input.consultation_output_hash,
        processing_activity_hash: null,
        processing_start_at: null,
        scope_hash: null,
        dpo_did_or_email_commit: null,
        dpo_advice_hash: null,
        dpia_artifact_hash: null,
        dpia_uri: null,
        residual_risk_level: null,
        review_due_at: null,
        review_outcome: null,
        review_evidence_hash: null,
        dpa_jurisdiction: null,
        submission_hash: null,
        dpa_advice_hash: null,
        dpa_did: null,
        controller_response_hash: null,
        terminal_disposition: null,
        termination_reason_hash: null,
        aer_receipt_ids: null,
        atr_receipt_ids: null,
        alr_receipt_ids: null,
        apur_receipt_ids: null,
        abr_receipt_id: null,
      };
      return body;
    }
    case "dpia.completed": {
      const body: AirCompletedBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.completed",
        dpia_artifact_hash: input.dpia_artifact_hash,
        dpia_uri: input.dpia_uri,
        residual_risk_level: input.residual_risk_level,
        review_due_at: input.review_due_at,
        aer_receipt_ids: input.aer_receipt_ids ?? null,
        atr_receipt_ids: input.atr_receipt_ids ?? null,
        alr_receipt_ids: input.alr_receipt_ids ?? null,
        apur_receipt_ids: input.apur_receipt_ids ?? null,
        processing_activity_hash: null,
        processing_start_at: null,
        scope_hash: null,
        dpo_did_or_email_commit: null,
        dpo_advice_hash: null,
        consultation_method: null,
        consultation_output_hash: null,
        review_outcome: null,
        review_evidence_hash: null,
        dpa_jurisdiction: null,
        submission_hash: null,
        dpa_advice_hash: null,
        dpa_did: null,
        controller_response_hash: null,
        terminal_disposition: null,
        termination_reason_hash: null,
        abr_receipt_id: null,
      };
      return body;
    }
    case "dpia.reviewed": {
      const body: AirReviewedBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.reviewed",
        review_outcome: input.review_outcome,
        review_evidence_hash: input.review_evidence_hash,
        abr_receipt_id: input.abr_receipt_id ?? null,
        processing_activity_hash: null,
        processing_start_at: null,
        scope_hash: null,
        dpo_did_or_email_commit: null,
        dpo_advice_hash: null,
        consultation_method: null,
        consultation_output_hash: null,
        dpia_artifact_hash: null,
        dpia_uri: null,
        residual_risk_level: null,
        review_due_at: null,
        dpa_jurisdiction: null,
        submission_hash: null,
        dpa_advice_hash: null,
        dpa_did: null,
        controller_response_hash: null,
        terminal_disposition: null,
        termination_reason_hash: null,
        aer_receipt_ids: null,
        atr_receipt_ids: null,
        alr_receipt_ids: null,
        apur_receipt_ids: null,
      };
      return body;
    }
    case "dpia.prior_consultation_initiated": {
      const body: AirPriorConsultationInitiatedBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.prior_consultation_initiated",
        dpa_jurisdiction: input.dpa_jurisdiction,
        submission_hash: input.submission_hash,
        processing_activity_hash: null,
        processing_start_at: null,
        scope_hash: null,
        dpo_did_or_email_commit: null,
        dpo_advice_hash: null,
        consultation_method: null,
        consultation_output_hash: null,
        dpia_artifact_hash: null,
        dpia_uri: null,
        residual_risk_level: null,
        review_due_at: null,
        review_outcome: null,
        review_evidence_hash: null,
        dpa_advice_hash: null,
        dpa_did: null,
        controller_response_hash: null,
        terminal_disposition: null,
        termination_reason_hash: null,
        aer_receipt_ids: null,
        atr_receipt_ids: null,
        alr_receipt_ids: null,
        apur_receipt_ids: null,
        abr_receipt_id: null,
      };
      return body;
    }
    case "dpia.prior_consultation_resolved": {
      const body: AirPriorConsultationResolvedBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.prior_consultation_resolved",
        dpa_advice_hash: input.dpa_advice_hash,
        controller_response_hash: input.controller_response_hash,
        dpa_did: input.dpa_did ?? null,
        processing_activity_hash: null,
        processing_start_at: null,
        scope_hash: null,
        dpo_did_or_email_commit: null,
        dpo_advice_hash: null,
        consultation_method: null,
        consultation_output_hash: null,
        dpia_artifact_hash: null,
        dpia_uri: null,
        residual_risk_level: null,
        review_due_at: null,
        review_outcome: null,
        review_evidence_hash: null,
        dpa_jurisdiction: null,
        submission_hash: null,
        terminal_disposition: null,
        termination_reason_hash: null,
        aer_receipt_ids: null,
        atr_receipt_ids: null,
        alr_receipt_ids: null,
        apur_receipt_ids: null,
        abr_receipt_id: null,
      };
      return body;
    }
    case "dpia.processing_authorised": {
      const body: AirProcessingAuthorisedBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.processing_authorised",
        terminal_disposition: "authorised",
        processing_activity_hash: null,
        processing_start_at: null,
        scope_hash: null,
        dpo_did_or_email_commit: null,
        dpo_advice_hash: null,
        consultation_method: null,
        consultation_output_hash: null,
        dpia_artifact_hash: null,
        dpia_uri: null,
        residual_risk_level: null,
        review_due_at: null,
        review_outcome: null,
        review_evidence_hash: null,
        dpa_jurisdiction: null,
        submission_hash: null,
        dpa_advice_hash: null,
        dpa_did: null,
        controller_response_hash: null,
        termination_reason_hash: null,
        aer_receipt_ids: null,
        atr_receipt_ids: null,
        alr_receipt_ids: null,
        apur_receipt_ids: null,
        abr_receipt_id: null,
      };
      return body;
    }
    case "dpia.processing_blocked": {
      const body: AirProcessingBlockedBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.processing_blocked",
        terminal_disposition: "blocked",
        processing_activity_hash: null,
        processing_start_at: null,
        scope_hash: null,
        dpo_did_or_email_commit: null,
        dpo_advice_hash: null,
        consultation_method: null,
        consultation_output_hash: null,
        dpia_artifact_hash: null,
        dpia_uri: null,
        residual_risk_level: null,
        review_due_at: null,
        review_outcome: null,
        review_evidence_hash: null,
        dpa_jurisdiction: null,
        submission_hash: null,
        dpa_advice_hash: null,
        dpa_did: null,
        controller_response_hash: null,
        termination_reason_hash: null,
        aer_receipt_ids: null,
        atr_receipt_ids: null,
        alr_receipt_ids: null,
        apur_receipt_ids: null,
        abr_receipt_id: null,
      };
      return body;
    }
    case "dpia.terminated": {
      const body: AirTerminatedBody = {
        ...baseBodyCommon(input),
        event_type: "dpia.terminated",
        terminal_disposition: "terminated",
        termination_reason_hash: input.termination_reason_hash,
        processing_activity_hash: null,
        processing_start_at: null,
        scope_hash: null,
        dpo_did_or_email_commit: null,
        dpo_advice_hash: null,
        consultation_method: null,
        consultation_output_hash: null,
        dpia_artifact_hash: null,
        dpia_uri: null,
        residual_risk_level: null,
        review_due_at: null,
        review_outcome: null,
        review_evidence_hash: null,
        dpa_jurisdiction: null,
        submission_hash: null,
        dpa_advice_hash: null,
        dpa_did: null,
        controller_response_hash: null,
        aer_receipt_ids: null,
        atr_receipt_ids: null,
        alr_receipt_ids: null,
        apur_receipt_ids: null,
        abr_receipt_id: null,
      };
      return body;
    }
  }
}

// ── mintAirV2 ─────────────────────────────────────────────────────────────────

export async function mintAirV2(input: MintAirV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAirV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintAirV2: signingKey.kid required");
  }
  if (input.signingKey.privateKey.length !== 32) {
    throw new Error("mintAirV2: signingKey.privateKey must be 32 bytes");
  }
  if (!input.anchor) throw new Error("mintAirV2: anchor required");
  if (!input.air_receipt_id) {
    throw new Error("mintAirV2: air_receipt_id required (D10-AIR-2)");
  }
  if (!input.processing_activity_id) {
    throw new Error("mintAirV2: processing_activity_id required (D10-AIR-3)");
  }

  // Event-specific validation.
  switch (input.event_type) {
    case "dpia.threshold_triggered":
      if (!isSha256Hex(input.processing_activity_hash)) {
        throw new Error(
          "mintAirV2: dpia.threshold_triggered requires processing_activity_hash as `sha256:<64-hex>`",
        );
      }
      if (!input.processing_start_at) {
        throw new Error(
          "mintAirV2: dpia.threshold_triggered requires processing_start_at",
        );
      }
      break;
    case "dpia.scope_locked":
      if (!isSha256Hex(input.scope_hash)) {
        throw new Error(
          "mintAirV2: dpia.scope_locked requires scope_hash as `sha256:<64-hex>`",
        );
      }
      break;
    case "dpia.dpo_advised":
      if (!isSha256Hex(input.dpo_did_or_email_commit)) {
        throw new Error(
          "mintAirV2: dpia.dpo_advised requires dpo_did_or_email_commit as `sha256:<64-hex>`",
        );
      }
      if (!isSha256Hex(input.dpo_advice_hash)) {
        throw new Error(
          "mintAirV2: dpia.dpo_advised requires dpo_advice_hash as `sha256:<64-hex>`",
        );
      }
      break;
    case "dpia.stakeholders_consulted":
      if (!isSha256Hex(input.consultation_output_hash)) {
        throw new Error(
          "mintAirV2: dpia.stakeholders_consulted requires consultation_output_hash as `sha256:<64-hex>`",
        );
      }
      // Subject + method gating (D10-AIR-6). Verifier §E enforces the same.
      if (input.subject !== undefined && input.subject !== null) {
        if (!isSha256Hex(input.subject)) {
          throw new Error(
            "mintAirV2: dpia.stakeholders_consulted subject must be `sha256:<64-hex>` or null (D10-AIR-6)",
          );
        }
        if (!SUBJECT_BEARING_METHODS.has(input.consultation_method)) {
          throw new Error(
            "mintAirV2: dpia.stakeholders_consulted subject is only permitted when consultation_method is `representative_org` or `ngo_review` (D10-AIR-6)",
          );
        }
      }
      break;
    case "dpia.completed":
      if (!isSha256Hex(input.dpia_artifact_hash)) {
        throw new Error(
          "mintAirV2: dpia.completed requires dpia_artifact_hash as `sha256:<64-hex>` (D10-AIR-7)",
        );
      }
      if (!input.dpia_uri) {
        throw new Error("mintAirV2: dpia.completed requires dpia_uri");
      }
      if (!input.review_due_at) {
        throw new Error("mintAirV2: dpia.completed requires review_due_at");
      }
      break;
    case "dpia.reviewed":
      if (!isSha256Hex(input.review_evidence_hash)) {
        throw new Error(
          "mintAirV2: dpia.reviewed requires review_evidence_hash as `sha256:<64-hex>`",
        );
      }
      break;
    case "dpia.prior_consultation_initiated":
      if (!input.dpa_jurisdiction || !isAirJurisdiction(input.dpa_jurisdiction)) {
        throw new Error(
          "mintAirV2: dpia.prior_consultation_initiated requires dpa_jurisdiction as ISO 3166-1 alpha-2 or `EU-EDPB`",
        );
      }
      if (!isSha256Hex(input.submission_hash)) {
        throw new Error(
          "mintAirV2: dpia.prior_consultation_initiated requires submission_hash as `sha256:<64-hex>`",
        );
      }
      break;
    case "dpia.prior_consultation_resolved":
      if (!isSha256Hex(input.dpa_advice_hash)) {
        throw new Error(
          "mintAirV2: dpia.prior_consultation_resolved requires dpa_advice_hash as `sha256:<64-hex>`",
        );
      }
      if (!isSha256Hex(input.controller_response_hash)) {
        throw new Error(
          "mintAirV2: dpia.prior_consultation_resolved requires controller_response_hash as `sha256:<64-hex>`",
        );
      }
      break;
    case "dpia.processing_authorised":
    case "dpia.processing_blocked":
      // Terminal disposition is pinned in the body builder; no extra required fields.
      break;
    case "dpia.terminated":
      if (!isSha256Hex(input.termination_reason_hash)) {
        throw new Error(
          "mintAirV2: dpia.terminated requires termination_reason_hash as `sha256:<64-hex>`",
        );
      }
      break;
  }

  if (input.tsa !== undefined && input.tsaFetcher === undefined) {
    throw new Error(
      "mintAirV2: tsaFetcher is required when tsa config is provided",
    );
  }

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: AirV2BodyOut = { ...baseBody, field_root };

  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined
      ? buildEnvelopeKind(input.event_type)
      : input.envelope_kind;

  // FAMILY-CONSISTENCY §3 + AIR §E subject resolution.
  // - dpia.stakeholders_consulted + caller-supplied sha256 + rep_org/ngo_review
  //     → subject = caller-supplied sha256 (validated above).
  // - dpia.stakeholders_consulted + caller-supplied null (or omitted)
  //     → subject = null.
  // - every other event_type → subject = null (input interface forbids supply).
  const subjectOut: string | null =
    input.event_type === "dpia.stakeholders_consulted" && input.subject
      ? input.subject
      : null;

  let preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: AIR_CLAIM_TYPE,
    iss: input.issuer,
    iss_key: issKey,
    subject: subjectOut as unknown as string,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    policy_uri: input.policy_uri,
    policy_hash: input.policy_hash,
    policy_version: input.policy_version,
    kind: envelopeKindOut,
    cause: input.cause ?? null,
    predicate: input.predicate ?? null,
    tsa: null,
    credentialStatus: null,
    anchor: input.anchor,
    sig: "",
    countersig: null,
    body: bodyOut,
  };

  if (input.statusList !== undefined) {
    preSign = await attachCredentialStatus(preSign, input.statusList);
  }

  if (input.suspensionList !== undefined) {
    preSign = await attachSuspensionStatus(preSign, input.suspensionList);
  }

  const signed = await signEnvelope(preSign, privateKey);

  if (input.tsa !== undefined) {
    return attachTsaBlock(signed, input.tsa, input.tsaFetcher!);
  }

  return signed;
}
