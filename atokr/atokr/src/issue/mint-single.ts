/**
 * Per-event-type convenience wrappers around `mintAtokrV2`.
 *
 * ATokR is v=2 only — there is no v=1 single-receipt path. These four functions
 * are thin adapters that narrow the discriminated input so call sites can
 * skip the `event_type: "..."` literal.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  mintAtokrV2,
  type MintTokenIssuedInput,
  type MintTokenRedeemedInput,
  type MintTokenRevokedInput,
  type MintTokenRotatedInput,
} from "./mint-v2.ts";

export type MintAtokrIssuedInput = Omit<MintTokenIssuedInput, "event_type">;
export type MintAtokrRedeemedInput = Omit<MintTokenRedeemedInput, "event_type">;
export type MintAtokrRevokedInput = Omit<MintTokenRevokedInput, "event_type">;
export type MintAtokrRotatedInput = Omit<MintTokenRotatedInput, "event_type">;

export function mintTokenIssued(input: MintAtokrIssuedInput): Promise<Envelope> {
  return mintAtokrV2({ ...input, event_type: "token.issued" });
}

export function mintTokenRedeemed(input: MintAtokrRedeemedInput): Promise<Envelope> {
  return mintAtokrV2({ ...input, event_type: "token.redeemed" });
}

export function mintTokenRevoked(input: MintAtokrRevokedInput): Promise<Envelope> {
  return mintAtokrV2({ ...input, event_type: "token.revoked" });
}

export function mintTokenRotated(input: MintAtokrRotatedInput): Promise<Envelope> {
  return mintAtokrV2({ ...input, event_type: "token.rotated" });
}
