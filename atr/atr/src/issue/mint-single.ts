/**
 * Per-event-type convenience wrappers around `mintAtrV2`.
 *
 * ATR is v=2 only — there is no v=1 single-receipt path. These four functions
 * are thin adapters that narrow the discriminated input so call sites can
 * skip the `event_type: "..."` literal.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  mintAtrV2,
  type MintArrangementInput,
  type MintTransferInput,
  type MintTiaInput,
  type MintSuspensionInput,
} from "./mint-v2.ts";

export type MintAtrArrangementInput = Omit<MintArrangementInput, "event_type">;
export type MintAtrTransferInput = Omit<MintTransferInput, "event_type">;
export type MintAtrTiaInput = Omit<MintTiaInput, "event_type">;
export type MintAtrSuspensionInput = Omit<MintSuspensionInput, "event_type">;

export function mintArrangement(input: MintAtrArrangementInput): Promise<Envelope> {
  return mintAtrV2({ ...input, event_type: "arrangement" });
}

export function mintTransfer(input: MintAtrTransferInput): Promise<Envelope> {
  return mintAtrV2({ ...input, event_type: "transfer" });
}

export function mintTia(input: MintAtrTiaInput): Promise<Envelope> {
  return mintAtrV2({ ...input, event_type: "tia" });
}

export function mintSuspension(input: MintAtrSuspensionInput): Promise<Envelope> {
  return mintAtrV2({ ...input, event_type: "suspension" });
}
