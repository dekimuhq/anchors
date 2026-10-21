/**
 * Per-event-type convenience wrappers around `mintAnrV2`.
 *
 * ANR is v=2 only — there is no v=1 single-receipt path. These six functions
 * are thin adapters that narrow the discriminated input so call sites can
 * skip the `event_type: "..."` literal. The verifier and the wire format
 * are unchanged.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  mintAnrV2,
  type MintAnrV2PresentedInput,
  type MintAnrV2RePresentedInput,
  type MintAnrV2AcknowledgedInput,
  type MintAnrV2WithdrawnInput,
  type MintAnrV2TranslatedInput,
  type MintAnrV2JointControllerEssenceInput,
} from "./mint-v2.ts";

export type MintPresentedInput = Omit<MintAnrV2PresentedInput, "event_type">;
export type MintRePresentedInput = Omit<MintAnrV2RePresentedInput, "event_type">;
export type MintAcknowledgedInput = Omit<MintAnrV2AcknowledgedInput, "event_type">;
export type MintWithdrawnInput = Omit<MintAnrV2WithdrawnInput, "event_type">;
export type MintTranslatedInput = Omit<MintAnrV2TranslatedInput, "event_type">;
export type MintJointControllerEssenceInput = Omit<
  MintAnrV2JointControllerEssenceInput,
  "event_type"
>;

export function mintPresented(input: MintPresentedInput): Promise<Envelope> {
  return mintAnrV2({ ...input, event_type: "notice.presented" });
}

export function mintRePresented(input: MintRePresentedInput): Promise<Envelope> {
  return mintAnrV2({ ...input, event_type: "notice.re_presented" });
}

export function mintAcknowledged(input: MintAcknowledgedInput): Promise<Envelope> {
  return mintAnrV2({ ...input, event_type: "notice.acknowledged" });
}

export function mintWithdrawn(input: MintWithdrawnInput): Promise<Envelope> {
  return mintAnrV2({ ...input, event_type: "notice.withdrawn" });
}

export function mintTranslated(input: MintTranslatedInput): Promise<Envelope> {
  return mintAnrV2({ ...input, event_type: "notice.translated" });
}

export function mintJointControllerEssence(
  input: MintJointControllerEssenceInput,
): Promise<Envelope> {
  return mintAnrV2({ ...input, event_type: "notice.joint_controller_essence" });
}
