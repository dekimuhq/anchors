/**
 * Subject-presence rule for ATR (FAMILY-CONSISTENCY.md §3, spec §3.1).
 *
 * ATR carries a per-event-type split:
 *
 *   - `transfer`   → `subject` MUST be `"sha256:<hex>"` (64 lowercase hex chars).
 *                    A transfer without a subject is meaningless — the receipt
 *                    binds to a specific data subject.
 *   - `arrangement`, `tia`, `suspension` → `subject` MUST be `null`.
 *                    These events describe controller-level acts, not per-subject
 *                    data flows; binding a subject would inflate the PII surface.
 *
 * The `event_type` discriminator is read directly off the envelope body (string
 * read; no full body validation). An unrecognised `event_type` is treated as
 * the must-be-null branch; the body verifier will reject the receipt for
 * `event_type.unknown` regardless.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/atr §3.1
 */

/** Format: `sha256:` + 64 lowercase hex chars (v1.1 envelope §5.4 salted commit). */
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

export type SubjectPresenceReason =
  | "subject_must_be_present"
  | "subject_must_be_sha256"
  | "subject_must_be_null";

export interface SubjectPresenceResult {
  ok: boolean;
  reason?: SubjectPresenceReason;
}

/** Per-event subject rule per FAMILY-CONSISTENCY.md §3. */
type EventRule = "must-be-sha256" | "must-be-null";

function ruleFor(eventType: unknown): EventRule {
  if (eventType === "transfer") return "must-be-sha256";
  // arrangement, tia, suspension — and any unknown event_type — require null
  return "must-be-null";
}

/**
 * FAMILY-CONSISTENCY §3: ATR per-event-type subject rule.
 *
 * Reads only `event_type` as a string discriminator; deeper body structure is
 * the §C body verifier's job. An unknown `event_type` falls through to the
 * must-be-null branch.
 */
export function checkAtrSubjectPresence(
  envelope: { subject: unknown; event_type: unknown },
): SubjectPresenceResult {
  const rule = ruleFor(envelope.event_type);
  const subject = envelope.subject;

  if (rule === "must-be-sha256") {
    if (typeof subject !== "string" || subject.length === 0) {
      return { ok: false, reason: "subject_must_be_present" };
    }
    if (!SHA256_HEX_RE.test(subject)) {
      return { ok: false, reason: "subject_must_be_sha256" };
    }
    return { ok: true };
  }

  // must-be-null
  if (subject !== null) {
    return { ok: false, reason: "subject_must_be_null" };
  }
  return { ok: true };
}
