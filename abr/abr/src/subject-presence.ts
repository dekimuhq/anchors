/**
 * Subject-presence rule for ABR (FAMILY-CONSISTENCY.md §3, spec §3.1 + §4.5 +
 * D10-ABR-4).
 *
 * Per-event-type split, stricter than ANR's:
 *
 *   - `breach.subject_notified` → `subject` MUST be `"sha256:<hex>"` (the
 *     Merkle batch root over the affected-subject `sub_commit` leaves;
 *     D10-ABR-4 binds the envelope subject to `body.subject_batch_root`).
 *   - every other `event_type` → `subject` MUST be `null` (incident-level
 *     events are not subject-scoped; `breach.subject_notification_exempted`
 *     is the exemption-level attestation per spec §4.6 and per
 *     FAMILY-CONSISTENCY §3 row 4 — `null`, not `either`).
 *
 * The `event_type` discriminator is read directly off the body (string-typed
 * read; no full body validation) so the check survives a malformed body —
 * the §C body verifier owns the deeper structural rules. An unrecognised
 * `event_type` is treated as the permissive (subject MUST be null) branch;
 * the body verifier will reject the receipt for `event_type.unknown`
 * regardless.
 *
 * The shared `Envelope` type declares `subject: string`, but the runtime
 * payload accepts `null` for families whose subject rule mandates it (cf.
 * APuR, ATR `arrangement`, ALR (any), ABR incident-level, ANR
 * jurisdiction-level events). The check below operates on the runtime
 * value, not the static type, so the type widening is honoured wherever
 * the family's row in §3 declares `null`.
 *
 * Hand-rolled rather than routed through `@dekimuhq/anchors-envelope`
 * `defineFamily()` because the factory's `checkSubjectPresence` only
 * supports universal `must-be-null` / `must-be-present` / `either` rules;
 * ABR's per-event-type split needs the body discriminator. ANR ships the
 * sibling per-event pattern; hoist into the shared factory once ≥1
 * additional sibling member ships the same shape.
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
  if (eventType === "breach.subject_notified") return "must-be-sha256";
  return "must-be-null";
}

/**
 * FAMILY-CONSISTENCY §3: ABR per-event-type subject rule.
 *
 * Reads the runtime `subject` value (rather than the static `Envelope.subject:
 * string` type) so receipts that legitimately carry `null` for incident-level
 * events are accepted.
 *
 * Reads only `body.event_type` as a string discriminator; deeper body
 * structure is the §C body verifier's job. An unknown `event_type` falls
 * through to the strict (must-be-null) branch — the body verifier rejects
 * unknown discriminators separately.
 */
export function checkAbrSubjectPresence(
  envelope: { subject: unknown; body: unknown },
): SubjectPresenceResult {
  const eventType =
    typeof envelope.body === "object" &&
    envelope.body !== null &&
    "event_type" in envelope.body
      ? (envelope.body as { event_type: unknown }).event_type
      : undefined;

  const rule = ruleFor(eventType);
  const subject = envelope.subject;

  if (rule === "must-be-sha256") {
    if (subject === null || (typeof subject === "string" && subject.length === 0)) {
      return { ok: false, reason: "subject_must_be_present" };
    }
    if (typeof subject !== "string" || !SHA256_HEX_RE.test(subject)) {
      return { ok: false, reason: "subject_must_be_sha256" };
    }
    return { ok: true };
  }

  // must-be-null
  if (subject === null) return { ok: true };
  return { ok: false, reason: "subject_must_be_null" };
}

/**
 * Surface used by `applyAbrSubjectPresence`. Matches the relevant subset of
 * `EnvelopeVerifyResult` — declared structurally to avoid cross-module deps.
 */
export interface AbrSubjectPresenceTarget {
  signature_valid: boolean;
  reason?: string;
}

/**
 * Apply the subject-presence rule to an envelope-verify result. Mutates
 * `target` only when the check fails — sets `signature_valid: false` and a
 * bare envelope-level reason code:
 *
 *   - `"subject_missing"`       — `breach.subject_notified` event missing a subject.
 *   - `"subject_invalid_form"`  — `breach.subject_notified` subject present but not `sha256:<hex>`.
 *   - `"subject_present"`       — incident-level event carrying a non-null subject.
 *
 * Bare codes (no `body_invalid:` prefix) per the family-wide convention that
 * envelope-level rejections use bare codes; body-level rejections prefix.
 *
 * Skipped (no-op) when `target.signature_valid` is already `false`; the
 * first failure wins and downstream checks do not overwrite it.
 */
export function applyAbrSubjectPresence(
  target: AbrSubjectPresenceTarget,
  envelope: { subject: unknown; body: unknown },
): void {
  if (!target.signature_valid) return;
  const r = checkAbrSubjectPresence(envelope);
  if (r.ok) return;
  target.signature_valid = false;
  switch (r.reason) {
    case "subject_must_be_present":
      target.reason = "subject_missing";
      return;
    case "subject_must_be_sha256":
      target.reason = "subject_invalid_form";
      return;
    case "subject_must_be_null":
      target.reason = "subject_present";
      return;
  }
}
