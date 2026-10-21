/**
 * Subject-presence rule for APuR (FAMILY-CONSISTENCY §3, spec §4).
 *
 * APuR is processing-activity-level: subject MUST be null on every event.
 * There is no per-event split — purpose receipts never bind to a specific
 * data subject.
 */

export type SubjectPresenceReason =
  | "subject_must_be_null";

export interface SubjectPresenceResult {
  ok: boolean;
  reason?: SubjectPresenceReason;
}

export function checkApurSubjectPresence(
  envelope: { subject: unknown },
): SubjectPresenceResult {
  if (envelope.subject !== null) {
    return { ok: false, reason: "subject_must_be_null" };
  }
  return { ok: true };
}
