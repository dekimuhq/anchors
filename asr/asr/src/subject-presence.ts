/**
 * ASR — subject-presence callback wired into the family manifest.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/asr §3.4 D10-ASR-5.
 *       Cross-family table: meta/FAMILY-CONSISTENCY.md §3.
 *
 * D10-ASR-5 — uniform across all 9 event types: subject MUST be a salted-commit
 * (`"sha256:<hex>"` form per v1.1 envelope §5.4) on every ASR receipt. Receipts
 * with `subject: null` reject as `subject_missing`; malformed sha256 prefix or
 * non-64-char hex rejects as `subject_invalid_form`. The factory's universal
 * `subject_presence: "must-be-present"` rule only enforces non-null — the
 * format check requires this callback.
 *
 * Reason codes are intentionally aligned with ANR's mapping
 * (`subject_missing` / `subject_invalid_form`) so the family-wide verifier
 * surface stays consistent for downstream tooling.
 */

import type { SubjectPresenceCheck } from "@dekimuhq/anchors-envelope";

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;

export const checkAsrSubjectPresence: SubjectPresenceCheck = ({ subject }) => {
  if (subject === null || subject === undefined || subject === "") {
    return { ok: false, reason: "subject_missing" };
  }
  if (typeof subject !== "string" || !SHA256_RE.test(subject)) {
    return { ok: false, reason: "subject_invalid_form" };
  }
  return { ok: true };
};
