/**
 * Subject-presence rule for ALR (FAMILY-CONSISTENCY.md §3).
 *
 * ALR `subject` MUST be `null` for every `event_type` — lineage is
 * dataset-level, not subject-level. Artifact discriminators ride on
 * `body.artifact_hash` (the receipt's own artifact) and on
 * `body.parents[].artifact_hash` / `body.successor.artifact_hash` (the
 * referenced upstream/downstream artifacts).
 *
 * The shared `Envelope` type declares `subject: string`, but the runtime
 * payload accepts `null` for families whose subject rule mandates it (cf.
 * APuR, ATR `arrangement`, ALR (any), ABR incident-level, ANR jurisdiction-
 * level). The check below operates on the runtime value, not the static
 * type, so the type widening is honoured wherever the family's row in §3
 * declares `null`.
 *
 * This is the first family-member implementation of a `subject-presence.ts`
 * module. The shape (Result + apply* helper) is the family-uniform template;
 * other members hold their own per-event rule tables. Do NOT hoist into
 * `@dekimuhq/anchors-envelope` until ≥2 sibling members have shipped and the
 * shared shape is proven; per the 10-spec batch plan, premature abstraction
 * is the larger risk than a third copy.
 */

import type { FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { alrFamily } from "./family.ts";

export type SubjectPresenceReason = "subject_must_be_null";

export interface SubjectPresenceResult {
  ok: boolean;
  reason?: SubjectPresenceReason;
}

/**
 * FAMILY-CONSISTENCY §3: ALR (any event_type) → subject MUST be null.
 *
 * Reads the runtime `subject` value (rather than the static `Envelope.subject:
 * string` type) so receipts that legitimately carry `null` are accepted.
 *
 * Phase A.2 wiring: delegates to the family manifest's `checkSubjectPresence`
 * helper (which encodes the `must-be-null` rule once for the whole protocol).
 * The local result/reason shape is preserved so callers stay byte-equal.
 */
export function checkAlrSubjectPresence(
  envelope: { subject: unknown },
): SubjectPresenceResult {
  const r = alrFamily.checkSubjectPresence(envelope.subject as string | null | undefined);
  if (r.ok) return { ok: true };
  return { ok: false, reason: "subject_must_be_null" };
}

/**
 * Surface used by `applyAlrSubjectPresence`. Matches the relevant subset of
 * `EnvelopeVerifyResult` — declared structurally so the module does not
 * create a circular import with `envelope-v2.ts`.
 */
export type AlrSubjectPresenceTarget = Pick<
  FamilyVerifyResult,
  "signature_valid" | "reason"
>;

/**
 * Apply the subject-presence rule to an envelope-verify result. Mutates
 * `target` only when the check fails — sets `signature_valid: false` and
 * `reason: "subject_present"`. The `reason` namespace mirrors `body_invalid:*`
 * — envelope-level rejections use bare reason codes; body-level rejections
 * use the `body_invalid:<detail>` prefix.
 *
 * Skipped (no-op) when `target.signature_valid` is already `false`; the
 * first failure wins and downstream checks do not overwrite it.
 */
export function applyAlrSubjectPresence(
  target: AlrSubjectPresenceTarget,
  envelope: { subject: unknown },
): void {
  if (!target.signature_valid) return;
  const r = checkAlrSubjectPresence(envelope);
  if (r.ok) return;
  target.signature_valid = false;
  target.reason = "subject_present";
}
