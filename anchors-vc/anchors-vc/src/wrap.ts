/**
 * Wrap an anchored receipt as a W3C Verifiable Credential carrier (Q1).
 *
 * The envelope is carried verbatim in `evidence[0].envelope`; a minimal lossless
 * field set is lifted to VC top-level. No re-canonicalisation, no re-signing —
 * `extractEnvelope(toVerifiableCredential(e))` is byte-equal to `e`.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import type {
  AnchoredReceiptCredential,
  AnchoredCredentialSubject,
} from "./types.ts";
import {
  VC_CONTEXT_V2,
  ANCHORS_VC_CONTEXT,
  ANCHORED_RECEIPT_CREDENTIAL_TYPE,
} from "./types.ts";

/**
 * Whether an envelope subject denotes an act/output rather than a data subject (Q4).
 *
 * Verified 2026-06-30 against `meta/FAMILY-CONSISTENCY.md §3` + the family
 * verifiers (e.g. `action/action/src/subject-presence.ts` `checkActionSubjectPresence`):
 * the on-wire null-subject value is literal `null`, uniform across every null-subject
 * family (AActR/AQR/AGR/AGrR/AgTR/APIIR/ACBR + the event-conditional null cases of
 * ATR/AER/ABR/AIR/APuR/ALR). There is no per-family magic-string sentinel — the
 * design-doc Q4 "sentinel table" resolved to plain `null`. The `Envelope.subject`
 * TS type says `string`, but the runtime value is `string | null`; treat it as such.
 */
export function isSubjectless(subject: string | null): boolean {
  return subject === null;
}

export interface ToVcOptions {
  /** Extra JSON-LD contexts appended after the base + anchors contexts. */
  contexts?: string[];
  /**
   * Force subjectless framing (Q4) regardless of the `subject === null` check.
   * Escape hatch for a caller that wants act-framing on a subject-bearing receipt.
   */
  subjectless?: boolean;
}

/** Wrap an anchored `Envelope` as an Anchored Receipt Verifiable Credential. */
export function toVerifiableCredential(
  envelope: Envelope,
  opts: ToVcOptions = {},
): AnchoredReceiptCredential {
  // Envelope.subject is typed `string` but is `string | null` on the wire for
  // null-subject families (verified — see isSubjectless). Read it defensively.
  const subject = (envelope as { subject: string | null }).subject;
  const subjectless = opts.subjectless ?? isSubjectless(subject);

  const credentialSubject: AnchoredCredentialSubject = subjectless
    ? { receipt: envelope.id, claimType: envelope.claim_type }
    : { id: subject as string };

  const context: [typeof VC_CONTEXT_V2, ...string[]] = [
    VC_CONTEXT_V2,
    ANCHORS_VC_CONTEXT,
    ...(opts.contexts ?? []),
  ];

  const vc: AnchoredReceiptCredential = {
    "@context": context,
    type: ["VerifiableCredential", ANCHORED_RECEIPT_CREDENTIAL_TYPE],
    issuer: envelope.iss,
    validFrom: envelope.iat,
    credentialSubject,
    evidence: [
      {
        type: ["AnchoredReceipt"],
        envelope,
        ...(envelope.anchor
          ? {
              anchorLog: envelope.anchor.log,
              treeHeadRoot: envelope.anchor.tree_head_root,
            }
          : {}),
      },
    ],
  };

  if (envelope.exp) {
    vc.validUntil = envelope.exp;
  }

  // credentialStatus parity (Q4): lift the envelope's StatusList2021Entry 1:1.
  if (envelope.credentialStatus && envelope.suspensionStatus) {
    vc.credentialStatus = [envelope.credentialStatus, envelope.suspensionStatus];
  } else if (envelope.credentialStatus) {
    vc.credentialStatus = envelope.credentialStatus;
  } else if (envelope.suspensionStatus) {
    vc.credentialStatus = envelope.suspensionStatus;
  }

  return vc;
}
