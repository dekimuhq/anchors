/**
 * Subject-presence rule for AER (FAMILY-CONSISTENCY.md §3, spec §4).
 *
 * AER has a per-event split:
 *   - `conformity`: subject MUST be null (system-level, not subject-level)
 *   - `transparency`: subject MUST be `"sha256:<hex>"` (end-user subject)
 *
 * Unknown event_type defaults to subject-must-be-null (strict branch).
 */

const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

export type SubjectPresenceReason =
  | "subject_must_be_null"
  | "subject_must_be_present"
  | "subject_must_be_sha256";

export interface SubjectPresenceResult {
  ok: boolean;
  reason?: SubjectPresenceReason;
}

export function checkAerSubjectPresence(
  envelope: { subject: unknown; body: unknown },
): SubjectPresenceResult {
  const body =
    typeof envelope.body === "object" && envelope.body !== null
      ? (envelope.body as { event_type?: unknown })
      : undefined;
  const eventType = body?.event_type;
  const subject = envelope.subject;

  if (eventType === "transparency") {
    if (typeof subject !== "string" || subject.length === 0) {
      return { ok: false, reason: "subject_must_be_present" };
    }
    if (!SHA256_HEX_RE.test(subject)) {
      return { ok: false, reason: "subject_must_be_sha256" };
    }
    return { ok: true };
  }

  // conformity + unknown event_type: subject MUST be null
  if (subject === null) return { ok: true };
  return { ok: false, reason: "subject_must_be_null" };
}
