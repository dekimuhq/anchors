/**
 * Recover the anchored receipt from its VC carrier (Q1).
 *
 * The returned `Envelope` is byte-equal to the minted receipt and is the value
 * to hand to the family's existing verifier — the VC wrapper carries no
 * cryptographic authority over the receipt itself.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import type { AnchoredReceiptCredential } from "./types.ts";
import { ANCHORED_RECEIPT_CREDENTIAL_TYPE } from "./types.ts";

export class AnchorsVcError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnchorsVcError";
  }
}

/** Type guard: structurally an Anchored Receipt carrier credential. */
export function isAnchoredReceiptCredential(
  value: unknown,
): value is AnchoredReceiptCredential {
  if (typeof value !== "object" || value === null) return false;
  const vc = value as Record<string, unknown>;
  if (!Array.isArray(vc.type)) return false;
  if (!vc.type.includes(ANCHORED_RECEIPT_CREDENTIAL_TYPE)) return false;
  if (!Array.isArray(vc.evidence) || vc.evidence.length === 0) return false;
  const ev = vc.evidence[0] as Record<string, unknown> | undefined;
  return !!ev && typeof ev.envelope === "object" && ev.envelope !== null;
}

/** Extract the embedded `Envelope` from an Anchored Receipt VC. */
export function extractEnvelope(vc: AnchoredReceiptCredential): Envelope {
  const ev = vc.evidence?.[0];
  if (!ev || typeof ev.envelope !== "object" || ev.envelope === null) {
    throw new AnchorsVcError(
      "no embedded AnchoredReceipt envelope in evidence[0]",
    );
  }
  return ev.envelope;
}
