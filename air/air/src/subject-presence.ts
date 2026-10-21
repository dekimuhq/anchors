/**
 * Subject-presence rule for AIR (FAMILY-CONSISTENCY.md §3, spec §4.4 +
 * D10-AIR-6).
 *
 * AIR is processing-activity-scoped, not subject-scoped. The envelope-level
 * `subject` MUST be `null` on every event EXCEPT OPTIONALLY on
 * `dpia.stakeholders_consulted`, where it MAY carry a salted-commit
 * (`"sha256:<hex>"` form per v1.1 envelope §5.4) of the consulted
 * representative organisation — AND ONLY when `body.consultation_method ∈
 * {"representative_org","ngo_review"}` (D10-AIR-6).
 *
 * Failure modes (bare envelope reason codes, no `body_invalid:` prefix —
 * envelope-level rejections use bare codes per the family convention):
 *
 *   - `subject_present`
 *       — any event_type other than `dpia.stakeholders_consulted` with a
 *         non-null `subject`. The processing-activity-scoped events are not
 *         subject-bearing.
 *   - `subject_invalid_form`
 *       — `dpia.stakeholders_consulted` with `subject` present but not
 *         `"sha256:<hex>"` (v1.1 envelope §5.4 salted-commit format).
 *   - `representative_subject_method_mismatch`
 *       — `dpia.stakeholders_consulted` with a syntactically valid
 *         `"sha256:<hex>"` `subject` but `body.consultation_method` ∉
 *         {`representative_org`, `ngo_review`}. Only representative-org and
 *         NGO-review consultations may anchor a subject commit; survey /
 *         focus_group / public_consultation / internal_advisory_panel /
 *         other MUST keep `subject: null`.
 *
 * `dpia.stakeholders_consulted` with `subject: null` always passes — the
 * D10-AIR-6 carve-out is OPTIONAL, so absence is the default-safe shape.
 *
 * The `event_type` and `consultation_method` discriminators are read
 * directly off the body (string-typed reads; no full body validation) so
 * the check survives a malformed body — the §C body verifier owns the
 * deeper structural rules. An unrecognised `event_type` is treated as the
 * strict (subject MUST be null) branch; the body verifier rejects unknown
 * discriminators separately.
 *
 * The shared `Envelope` type declares `subject: string`, but the runtime
 * payload accepts `null` for families whose subject rule mandates it (cf.
 * APuR, ATR `arrangement`, ALR (any), ABR incident-level, ANR
 * jurisdiction-level, AIR (any except representative-org / NGO-review
 * stakeholder consultation)). The check below operates on the runtime
 * value, not the static type.
 *
 * Hand-rolled rather than routed through `@dekimuhq/anchors-envelope`
 * `defineFamily()` because the factory's `checkSubjectPresence` only
 * supports universal `must-be-null` / `must-be-present` / `either` rules;
 * AIR's per-event-type carve-out additionally needs the body's
 * `consultation_method` discriminator. ABR + ANR ship the sibling
 * per-event pattern; hoist into the shared factory once ≥1 additional
 * sibling member ships a comparable shape.
 */

import type { FamilyVerifyResult } from "@dekimuhq/anchors-envelope";

/** Format: `sha256:` + 64 lowercase hex chars (v1.1 envelope §5.4 salted commit). */
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

/** Consultation methods that MAY anchor a representative-org `sub_commit` (D10-AIR-6). */
const SUBJECT_BEARING_METHODS: ReadonlySet<string> = new Set([
  "representative_org",
  "ngo_review",
]);

export type SubjectPresenceReason =
  | "subject_must_be_null"
  | "subject_must_be_sha256"
  | "method_disallows_subject";

export interface SubjectPresenceResult {
  ok: boolean;
  reason?: SubjectPresenceReason;
}

/**
 * FAMILY-CONSISTENCY §3: AIR per-event-type subject rule with the
 * `dpia.stakeholders_consulted` representative-org / NGO-review carve-out.
 *
 * Reads the runtime `subject` value (rather than the static `Envelope.subject:
 * string` type) so receipts that legitimately carry `null` are accepted.
 *
 * Reads only `body.event_type` and (on stakeholders_consulted)
 * `body.consultation_method` as string discriminators; deeper body
 * structure is the §C body verifier's job.
 */
export function checkAirSubjectPresence(
  envelope: { subject: unknown; body: unknown },
): SubjectPresenceResult {
  const body =
    typeof envelope.body === "object" && envelope.body !== null
      ? (envelope.body as { event_type?: unknown; consultation_method?: unknown })
      : undefined;
  const eventType = body?.event_type;
  const subject = envelope.subject;

  if (eventType === "dpia.stakeholders_consulted") {
    if (subject === null) return { ok: true };
    if (typeof subject !== "string" || !SHA256_HEX_RE.test(subject)) {
      return { ok: false, reason: "subject_must_be_sha256" };
    }
    const method = body?.consultation_method;
    if (typeof method !== "string" || !SUBJECT_BEARING_METHODS.has(method)) {
      return { ok: false, reason: "method_disallows_subject" };
    }
    return { ok: true };
  }

  // Every other event_type (including unknown discriminators): subject MUST
  // be null. The body verifier separately rejects unknown event_type values.
  if (subject === null) return { ok: true };
  return { ok: false, reason: "subject_must_be_null" };
}

/**
 * Surface used by `applyAirSubjectPresence`. Matches the relevant subset of
 * `EnvelopeVerifyResult` — declared structurally so the module does not
 * create a circular import with `envelope-v2.ts`.
 */
export type AirSubjectPresenceTarget = Pick<
  FamilyVerifyResult,
  "signature_valid" | "reason"
>;

/**
 * Apply the subject-presence rule to an envelope-verify result. Mutates
 * `target` only when the check fails — sets `signature_valid: false` and a
 * bare envelope-level reason code:
 *
 *   - `"subject_present"`                          — non-null subject on a non-stakeholders_consulted event.
 *   - `"subject_invalid_form"`                     — stakeholders_consulted subject present but not `sha256:<hex>`.
 *   - `"representative_subject_method_mismatch"`   — valid sha256 subject on stakeholders_consulted but method not in {representative_org, ngo_review}.
 *
 * Bare codes (no `body_invalid:` prefix) per the family-wide convention that
 * envelope-level rejections use bare codes; body-level rejections prefix.
 *
 * Skipped (no-op) when `target.signature_valid` is already `false`; the
 * first failure wins and downstream checks do not overwrite it.
 */
export function applyAirSubjectPresence(
  target: AirSubjectPresenceTarget,
  envelope: { subject: unknown; body: unknown },
): void {
  if (!target.signature_valid) return;
  const r = checkAirSubjectPresence(envelope);
  if (r.ok) return;
  target.signature_valid = false;
  switch (r.reason) {
    case "subject_must_be_null":
      target.reason = "subject_present";
      return;
    case "subject_must_be_sha256":
      target.reason = "subject_invalid_form";
      return;
    case "method_disallows_subject":
      target.reason = "representative_subject_method_mismatch";
      return;
  }
}
