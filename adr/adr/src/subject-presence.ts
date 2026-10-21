/**
 * Subject-presence rule for ADR (FAMILY-CONSISTENCY §3, spec §4.3).
 *
 * ADR: every event MUST carry `subject = "sha256:<hex>"` (64 lowercase hex).
 * The subject is the principal_commit — HMAC-pseudonymised delegator identity.
 */

const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

export type AdrSubjectPresenceReason =
  | "subject_must_be_present"
  | "subject_must_be_sha256";

export interface AdrSubjectPresenceResult {
  readonly ok: boolean;
  readonly reason?: AdrSubjectPresenceReason;
}

export function checkAdrSubjectPresence(
  envelope: { subject: unknown },
): AdrSubjectPresenceResult {
  const subject = envelope.subject;
  if (typeof subject !== "string" || subject.length === 0) {
    return { ok: false, reason: "subject_must_be_present" };
  }
  if (!SHA256_HEX_RE.test(subject)) {
    return { ok: false, reason: "subject_must_be_sha256" };
  }
  return { ok: true };
}
