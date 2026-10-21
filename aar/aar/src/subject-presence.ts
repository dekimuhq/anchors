/**
 * Subject-presence rule for AAR (FAMILY-CONSISTENCY.md §3, spec §3.1).
 *
 * Every AAR event MUST carry `subject = "sha256:<hex>"` (64 lowercase hex
 * chars). The subject binds the receipt to the eIDAS qualified attestation
 * or certificate being tracked — a receipt without a subject is meaningless.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/aar §3.1
 */

/** Format: `sha256:` + 64 lowercase hex chars (v1.1 envelope §5.4 salted commit). */
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

export type SubjectPresenceReason =
  | "subject_must_be_present"
  | "subject_must_be_sha256";

export interface SubjectPresenceResult {
  ok: boolean;
  reason?: SubjectPresenceReason;
}

/**
 * FAMILY-CONSISTENCY §3: AAR universal subject rule.
 *
 * Every event MUST carry `subject = "sha256:<hex>"`. A receipt without a
 * subject cannot be meaningfully associated with a specific eIDAS service
 * recipient.
 */
export function checkAarSubjectPresence(
  envelope: { subject: unknown },
): SubjectPresenceResult {
  const subject = envelope.subject;
  if (typeof subject !== "string" || subject.length === 0) {
    return { ok: false, reason: "subject_must_be_present" };
  }
  if (!SHA256_HEX_RE.test(subject)) {
    return { ok: false, reason: "subject_must_be_sha256" };
  }
  return { ok: true };
}
