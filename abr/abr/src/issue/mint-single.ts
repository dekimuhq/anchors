/**
 * Per-event-type convenience wrappers around `mintAbrV2`.
 *
 * ABR is v=2 only — there is no v=1 single-receipt path. These eight functions
 * are thin adapters that narrow the discriminated input so call sites can
 * skip the `event_type: "..."` literal. The verifier and the wire format
 * are unchanged.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  mintAbrV2,
  type MintAbrV2DetectedInput,
  type MintAbrV2AssessedInput,
  type MintAbrV2DpaNotifiedInput,
  type MintAbrV2DpaDelayedInput,
  type MintAbrV2SubjectNotifiedInput,
  type MintAbrV2SubjectNotificationExemptedInput,
  type MintAbrV2ContainedInput,
  type MintAbrV2ClosedInput,
} from "./mint-v2.ts";

export type MintDetectedInput = Omit<MintAbrV2DetectedInput, "event_type">;
export type MintAssessedInput = Omit<MintAbrV2AssessedInput, "event_type">;
export type MintDpaNotifiedInput = Omit<MintAbrV2DpaNotifiedInput, "event_type">;
export type MintDpaDelayedInput = Omit<MintAbrV2DpaDelayedInput, "event_type">;
export type MintSubjectNotifiedInput = Omit<
  MintAbrV2SubjectNotifiedInput,
  "event_type"
>;
export type MintSubjectNotificationExemptedInput = Omit<
  MintAbrV2SubjectNotificationExemptedInput,
  "event_type"
>;
export type MintContainedInput = Omit<MintAbrV2ContainedInput, "event_type">;
export type MintClosedInput = Omit<MintAbrV2ClosedInput, "event_type">;

export function mintDetected(input: MintDetectedInput): Promise<Envelope> {
  return mintAbrV2({ ...input, event_type: "breach.detected" });
}

export function mintAssessed(input: MintAssessedInput): Promise<Envelope> {
  return mintAbrV2({ ...input, event_type: "breach.assessed" });
}

export function mintDpaNotified(input: MintDpaNotifiedInput): Promise<Envelope> {
  return mintAbrV2({ ...input, event_type: "breach.dpa_notified" });
}

export function mintDpaDelayed(input: MintDpaDelayedInput): Promise<Envelope> {
  return mintAbrV2({ ...input, event_type: "breach.dpa_delayed" });
}

export function mintSubjectNotified(
  input: MintSubjectNotifiedInput,
): Promise<Envelope> {
  return mintAbrV2({ ...input, event_type: "breach.subject_notified" });
}

export function mintSubjectNotificationExempted(
  input: MintSubjectNotificationExemptedInput,
): Promise<Envelope> {
  return mintAbrV2({ ...input, event_type: "breach.subject_notification_exempted" });
}

export function mintContained(input: MintContainedInput): Promise<Envelope> {
  return mintAbrV2({ ...input, event_type: "breach.contained" });
}

export function mintClosed(input: MintClosedInput): Promise<Envelope> {
  return mintAbrV2({ ...input, event_type: "breach.closed" });
}
