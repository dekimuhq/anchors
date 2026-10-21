/**
 * Per-event-type convenience wrappers around `mintAirV2`.
 *
 * AIR is v=2 only — there is no v=1 single-receipt path. These eleven
 * functions are thin adapters that narrow the discriminated input so call
 * sites can skip the `event_type: "..."` literal. The verifier and the wire
 * format are unchanged.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  mintAirV2,
  type MintAirV2ThresholdTriggeredInput,
  type MintAirV2ScopeLockedInput,
  type MintAirV2DpoAdvisedInput,
  type MintAirV2StakeholdersConsultedInput,
  type MintAirV2CompletedInput,
  type MintAirV2ReviewedInput,
  type MintAirV2PriorConsultationInitiatedInput,
  type MintAirV2PriorConsultationResolvedInput,
  type MintAirV2ProcessingAuthorisedInput,
  type MintAirV2ProcessingBlockedInput,
  type MintAirV2TerminatedInput,
} from "./mint-v2.ts";

export type MintThresholdTriggeredInput = Omit<
  MintAirV2ThresholdTriggeredInput,
  "event_type"
>;
export type MintScopeLockedInput = Omit<MintAirV2ScopeLockedInput, "event_type">;
export type MintDpoAdvisedInput = Omit<MintAirV2DpoAdvisedInput, "event_type">;
export type MintStakeholdersConsultedInput = Omit<
  MintAirV2StakeholdersConsultedInput,
  "event_type"
>;
export type MintCompletedInput = Omit<MintAirV2CompletedInput, "event_type">;
export type MintReviewedInput = Omit<MintAirV2ReviewedInput, "event_type">;
export type MintPriorConsultationInitiatedInput = Omit<
  MintAirV2PriorConsultationInitiatedInput,
  "event_type"
>;
export type MintPriorConsultationResolvedInput = Omit<
  MintAirV2PriorConsultationResolvedInput,
  "event_type"
>;
export type MintProcessingAuthorisedInput = Omit<
  MintAirV2ProcessingAuthorisedInput,
  "event_type"
>;
export type MintProcessingBlockedInput = Omit<
  MintAirV2ProcessingBlockedInput,
  "event_type"
>;
export type MintTerminatedInput = Omit<MintAirV2TerminatedInput, "event_type">;

export function mintThresholdTriggered(
  input: MintThresholdTriggeredInput,
): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.threshold_triggered" });
}

export function mintScopeLocked(input: MintScopeLockedInput): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.scope_locked" });
}

export function mintDpoAdvised(input: MintDpoAdvisedInput): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.dpo_advised" });
}

export function mintStakeholdersConsulted(
  input: MintStakeholdersConsultedInput,
): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.stakeholders_consulted" });
}

export function mintCompleted(input: MintCompletedInput): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.completed" });
}

export function mintReviewed(input: MintReviewedInput): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.reviewed" });
}

export function mintPriorConsultationInitiated(
  input: MintPriorConsultationInitiatedInput,
): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.prior_consultation_initiated" });
}

export function mintPriorConsultationResolved(
  input: MintPriorConsultationResolvedInput,
): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.prior_consultation_resolved" });
}

export function mintProcessingAuthorised(
  input: MintProcessingAuthorisedInput,
): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.processing_authorised" });
}

export function mintProcessingBlocked(
  input: MintProcessingBlockedInput,
): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.processing_blocked" });
}

export function mintTerminated(input: MintTerminatedInput): Promise<Envelope> {
  return mintAirV2({ ...input, event_type: "dpia.terminated" });
}
