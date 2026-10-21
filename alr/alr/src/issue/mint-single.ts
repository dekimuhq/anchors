/**
 * Per-event-type convenience wrappers around `mintAlrV2`.
 *
 * ALR is v=2 only — there is no v=1 single-receipt path. These four functions
 * are thin adapters that narrow the discriminated input so call sites can
 * skip the `event_type: "..."` literal. The verifier and the wire format
 * are unchanged.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  mintAlrV2,
  type MintAlrV2DerivedFromInput,
  type MintAlrV2ForkedFromInput,
  type MintAlrV2SupersededByInput,
  type MintAlrV2DisclosedInput,
} from "./mint-v2.ts";

export type MintDerivedFromInput = Omit<MintAlrV2DerivedFromInput, "event_type">;
export type MintForkedFromInput = Omit<MintAlrV2ForkedFromInput, "event_type">;
export type MintSupersededByInput = Omit<MintAlrV2SupersededByInput, "event_type">;
export type MintDisclosedInput = Omit<MintAlrV2DisclosedInput, "event_type">;

export function mintDerivedFrom(input: MintDerivedFromInput): Promise<Envelope> {
  return mintAlrV2({ ...input, event_type: "derived_from" });
}

export function mintForkedFrom(input: MintForkedFromInput): Promise<Envelope> {
  return mintAlrV2({ ...input, event_type: "forked_from" });
}

export function mintSupersededBy(input: MintSupersededByInput): Promise<Envelope> {
  return mintAlrV2({ ...input, event_type: "superseded_by" });
}

export function mintDisclosed(input: MintDisclosedInput): Promise<Envelope> {
  return mintAlrV2({ ...input, event_type: "disclosed" });
}
