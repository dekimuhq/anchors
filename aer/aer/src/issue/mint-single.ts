/**
 * Per-event-type convenience wrappers around `mintAerV2`.
 *
 * AER is v=2 only — there is no v=1 single-receipt path. These two functions
 * are thin adapters that narrow the discriminated input so call sites can
 * skip the `event_type: "..."` literal.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  mintAerV2,
  type MintAerConformityInput,
  type MintAerTransparencyInput,
} from "./mint-v2.ts";

export type MintConformityInput = Omit<MintAerConformityInput, "event_type">;
export type MintTransparencyInput = Omit<MintAerTransparencyInput, "event_type">;

export function mintConformity(input: MintConformityInput): Promise<Envelope> {
  return mintAerV2({ ...input, event_type: "conformity" });
}

export function mintTransparency(input: MintTransparencyInput): Promise<Envelope> {
  return mintAerV2({ ...input, event_type: "transparency" });
}
