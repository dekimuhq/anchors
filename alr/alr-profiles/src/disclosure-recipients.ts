/**
 * `disclosure.recipients` profile validator — ALR spec §5.5.
 *
 * Hook: GDPR Art 19 (rectification/erasure cascade) + Art 15(1)(c) (subject
 * right to know recipients). The folded-in `disclosed` event-type profile.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"disclosure.recipients"`.
 *   - `body.event_type` MUST be exactly `"disclosed"` (spec §5.5 row 1).
 *   - `body.disclosure.recipient_role` MUST be one of:
 *       `controller`, `processor`, `joint-controller`, `recipient`,
 *       `third-country-recipient`.
 *
 * Spec extras `sub_commit` REQUIRED and `art19_notified: boolean` are not
 * represented in `AlrBody` v1.0 — deferred to v1.1 per spec §10.2.
 */

import type { AlrBody } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const DISCLOSURE_RECIPIENTS_PROFILE_ID =
  "disclosure.recipients" as const;

/**
 * Spec §5.5 row 2 — controlled vocabulary of recipient roles. Mirrors the
 * GDPR-aligned Art 4(9) classification plus the eIDAS-friendly
 * `third-country-recipient` (Art 49 transfer leg).
 */
const ALLOWED_RECIPIENT_ROLES: ReadonlySet<string> = new Set([
  "controller",
  "processor",
  "joint-controller",
  "recipient",
  "third-country-recipient",
]);

export function validateDisclosureRecipients(
  body: AlrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== DISCLOSURE_RECIPIENTS_PROFILE_ID) {
    errors.push("disclosure.recipients.profile.mismatch");
    return { errors };
  }

  if (body.event_type !== "disclosed") {
    errors.push("disclosure.recipients.event_type.disallowed");
    return { errors };
  }

  // `disclosed` bodies must carry a non-null `disclosure` block per §C body
  // validation; defensive check here keeps the validator independent of the
  // §C precondition (validators MAY run on body shapes that bypassed §C).
  if (!body.disclosure) {
    errors.push("disclosure.recipients.disclosure.required");
    return { errors };
  }

  if (!ALLOWED_RECIPIENT_ROLES.has(body.disclosure.recipient_role)) {
    errors.push("disclosure.recipients.recipient_role.disallowed");
  }

  return { errors };
}

export const validateDisclosureRecipientsProfile = makeProfileAdapter(DISCLOSURE_RECIPIENTS_PROFILE_ID, (body) => validateDisclosureRecipients(body as AlrBody));
