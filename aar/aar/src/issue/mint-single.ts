/**
 * Per-event-type convenience wrappers around `mintAarV2`.
 *
 * AAR is v=2 only — there is no v=1 single-receipt path. These two functions
 * are thin adapters that narrow the discriminated input so call sites can
 * skip the `event_type: "..."` literal.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  mintAarV2,
  type MintAarIssuanceInput,
  type MintAarRevocationInput,
} from "./mint-v2.ts";

export type MintIssuanceInput = Omit<MintAarIssuanceInput, "event_type">;
export type MintRevocationInput = Omit<MintAarRevocationInput, "event_type">;

export function mintIssuance(input: MintIssuanceInput): Promise<Envelope> {
  return mintAarV2({ ...input, event_type: "issuance" });
}

export function mintRevocation(input: MintRevocationInput): Promise<Envelope> {
  return mintAarV2({ ...input, event_type: "revocation" });
}
