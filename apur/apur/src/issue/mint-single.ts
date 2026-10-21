/**
 * Per-event-type convenience wrappers around `mintApurV2`.
 *
 * APuR is v=2 only — there is no v=1 single-receipt path. These three functions
 * are thin adapters that narrow the discriminated input so call sites can
 * skip the `event_type: "..."` literal.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  mintApurV2,
  type MintBindingInput,
  type MintRepurposeInput,
  type MintUnbindingInput,
} from "./mint-v2.ts";

export type MintApurBindingInput = Omit<MintBindingInput, "event_type">;
export type MintApurRepurposeInput = Omit<MintRepurposeInput, "event_type">;
export type MintApurUnbindingInput = Omit<MintUnbindingInput, "event_type">;

export function mintBinding(input: MintApurBindingInput): Promise<Envelope> {
  return mintApurV2({ ...input, event_type: "binding" });
}

export function mintRepurpose(input: MintApurRepurposeInput): Promise<Envelope> {
  return mintApurV2({ ...input, event_type: "repurpose" });
}

export function mintUnbinding(input: MintApurUnbindingInput): Promise<Envelope> {
  return mintApurV2({ ...input, event_type: "unbinding" });
}
