/**
 * Subject-presence rule for ANR (FAMILY-CONSISTENCY.md §3, spec §3.1 + §4.3).
 *
 * Unlike ALR (universal-null) and ACR/ARR/ASR (universal-present), ANR carries
 * a per-event-type split:
 *
 *   - `notice.acknowledged` → `subject` MUST be `"sha256:<hex>"` (per-subject
 *     ack: an acknowledgement without a subject is meaningless).
 *   - every other event_type → `subject` MAY be `"sha256:<hex>"` OR `null`
 *     (jurisdiction-level notices have no subject context).
 *
 * The `event_type` discriminator is read directly off the body (string-typed
 * read; no full body validation) so the check survives a malformed body — the
 * §C body verifier owns the deeper structural rules. An unrecognised
 * `event_type` is treated as the permissive (non-ack) branch; the body
 * verifier will reject the receipt for `event_type.unknown` regardless.
 *
 * The shared `Envelope` type declares `subject: string`, but the runtime
 * payload accepts `null` for families whose subject rule mandates it (cf.
 * APuR, ATR `arrangement`, ALR (any), ABR incident-level, ANR
 * jurisdiction-level events). The check below operates on the runtime value,
 * not the static type, so the type widening is honoured wherever the
 * family's row in §3 declares `null`.
 *
 * Hand-rolled rather than routed through `@dekimuhq/anchors-envelope`
 * `defineFamily()` because the factory's `checkSubjectPresence` only supports
 * universal `must-be-null` / `must-be-present` / `either` rules; ANR's
 * per-event-type split needs the body discriminator. Defer hoist until ≥2
 * sibling members ship the per-event pattern.
 */

import type { FamilyVerifyResult as EnvelopeVerifyResult } from "@dekimuhq/anchors-envelope";

/** Format: `sha256:` + 64 lowercase hex chars (v1.1 envelope §5.4 salted commit). */
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

export type SubjectPresenceReason =
  | "subject_must_be_present"
  | "subject_must_be_sha256";

export interface SubjectPresenceResult {
  ok: boolean;
  reason?: SubjectPresenceReason;
}

/** Per-event subject rule per FAMILY-CONSISTENCY.md §3. */
type EventRule = "must-be-sha256" | "sha256-or-null";

function ruleFor(eventType: unknown): EventRule {
  if (eventType === "notice.acknowledged") return "must-be-sha256";
  return "sha256-or-null";
}

/**
 * FAMILY-CONSISTENCY §3: ANR per-event-type subject rule.
 *
 * Reads the runtime `subject` value (rather than the static `Envelope.subject:
 * string` type) so receipts that legitimately carry `null` for
 * jurisdiction-level events are accepted.
 *
 * Reads only `body.event_type` as a string discriminator; deeper body
 * structure is the §C body verifier's job. An unknown `event_type` falls
 * through to the permissive (non-ack) branch — the body verifier rejects
 * unknown discriminators separately.
 */
export function checkAnrSubjectPresence(
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
    if (typeof subject !== "string" || subject.length === 0) {
      return { ok: false, reason: "subject_must_be_present" };
    }
    if (!SHA256_HEX_RE.test(subject)) {
      return { ok: false, reason: "subject_must_be_sha256" };
    }
    return { ok: true };
  }

  // sha256-or-null
  if (subject === null) return { ok: true };
  if (typeof subject === "string" && SHA256_HEX_RE.test(subject)) {
    return { ok: true };
  }
  return { ok: false, reason: "subject_must_be_sha256" };
}

/**
 * Surface used by `applyAnrSubjectPresence`. Matches the relevant subset of
 * `EnvelopeVerifyResult` — declared structurally so the module does not
 * create a circular import with `envelope-v2.ts`.
 */
export type AnrSubjectPresenceTarget = Pick<
  EnvelopeVerifyResult,
  "signature_valid" | "reason"
>;

/**
 * Apply the subject-presence rule to an envelope-verify result. Mutates
 * `target` only when the check fails — sets `signature_valid: false` and a
 * bare envelope-level reason code:
 *
 *   - `"subject_missing"`       — ack event missing a subject.
 *   - `"subject_invalid_form"`  — subject present but not `sha256:<hex>`.
 *
 * Bare codes (no `body_invalid:` prefix) per the family-wide convention that
 * envelope-level rejections use bare codes; body-level rejections prefix.
 *
 * Skipped (no-op) when `target.signature_valid` is already `false`; the
 * first failure wins and downstream checks do not overwrite it.
 */
export function applyAnrSubjectPresence(
  target: AnrSubjectPresenceTarget,
  envelope: { subject: unknown; body: unknown },
): void {
  if (!target.signature_valid) return;
  const r = checkAnrSubjectPresence(envelope);
  if (r.ok) return;
  target.signature_valid = false;
  target.reason =
    r.reason === "subject_must_be_present"
      ? "subject_missing"
      : "subject_invalid_form";
}
