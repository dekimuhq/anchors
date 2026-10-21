/**
 * Subject-presence rule for AActR (FAMILY-CONSISTENCY §3, spec §4 decision 2).
 *
 * AActR is workspace/activity-level: subject MUST be null on every receipt.
 * There is no per-event split — an action receipt never binds to a specific
 * data subject. The action's *target* lives in the body as a salted commit, not
 * in the envelope `subject`.
 */

export type SubjectPresenceReason = "subject_must_be_null";

export interface SubjectPresenceResult {
  ok: boolean;
  reason?: SubjectPresenceReason;
}

export function checkActionSubjectPresence(envelope: {
  subject: unknown;
}): SubjectPresenceResult {
  if (envelope.subject !== null) {
    return { ok: false, reason: "subject_must_be_null" };
  }
  return { ok: true };
}
