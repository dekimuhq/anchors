/**
 * Subject-presence rule for ATokR (FAMILY-CONSISTENCY.md §3, spec §3.1).
 *
 * ATokR is the simplest family member for subject-presence: every event MUST
 * carry `subject = "sha256:<hex>"` (64 lowercase hex chars). There is no
 * per-event split — tokenization receipts always bind to a specific subject
 * (the token holder / data subject whose PAN / email / IBAN / etc. was
 * tokenized).
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/atokr §3.1
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
 * FAMILY-CONSISTENCY §3: ATokR universal subject rule.
 *
 * Every event MUST carry `subject = "sha256:<hex>"`. Unlike ANR (per-event
 * split) or ALR (universal-null), ATokR has no permissive branch: a receipt
 * without a subject is meaningless — the token lifecycle is always tied to a
 * specific subject.
 */
export function checkAtokrSubjectPresence(
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
